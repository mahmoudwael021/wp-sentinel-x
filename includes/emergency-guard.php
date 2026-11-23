<?php
if (!defined('ABSPATH')) exit;
/** Emergency containment. Does not execute untrusted content. */
final class WPSX_Emergency_Guard {
 const OPT='wpsx_emergency_guard'; const INVENTORY='wpsx_emergency_plugins';
 static function settings(){return wp_parse_args(get_option(self::OPT,[]),['lock_installs'=>1,'auto_shell'=>1,'plugin_watch'=>1,'auto_zip'=>1]);}
 static function init(){
  add_action('admin_menu',[__CLASS__,'menu'],45);
  add_action('admin_post_wpsx_emergency_save',[__CLASS__,'save']);
  add_action('admin_post_wpsx_emergency_run',[__CLASS__,'manual']);
  add_filter('file_mod_allowed',[__CLASS__,'file_mod_allowed'],999,2);
  add_action('admin_init',[__CLASS__,'watch_plugins'],2);
  add_action('wpsx_auto_recovery_cron',[__CLASS__,'run'],5);
  add_action('wpsx_scan_event',[__CLASS__,'run'],5);
 }
 static function file_mod_allowed($allowed,$context){
  if(!empty(self::settings()['lock_installs']) && in_array($context,['capability_update_core','capability_update_plugins','capability_update_themes','capability_install_plugins','capability_install_themes','capability_delete_plugins','capability_delete_themes','capability_edit_plugins','capability_edit_themes','automatic_updater','plugin','theme'],true))return false;
  return $allowed;
 }
 static function inventory(){if(!function_exists('get_plugins'))require_once ABSPATH.'wp-admin/includes/plugin.php';return array_keys(get_plugins());}
 static function watch_plugins(){
  if(empty(self::settings()['plugin_watch']))return;
  $now=self::inventory();$old=get_option(self::INVENTORY,null);
  if(!is_array($old)){update_option(self::INVENTORY,$now,false);WPSX::log('plugin_guard','Plugin inventory initialized; existing plugins need manual review','warning');return;}
  $new=array_diff($now,$old);$removed=array_diff($old,$now);
  if($new){WPSX::log('plugin_guard','NEW plugin files: '.implode(', ',array_slice($new,0,12)),'critical');}
  if($removed)WPSX::log('plugin_guard','Removed plugin entries: '.implode(', ',array_slice($removed,0,12)),'warning');
  if($new||$removed)update_option(self::INVENTORY,$now,false);
 }
 static function shell_signature($body){
  if(!is_string($body)||strlen($body)<1000)return false;
  $fileOps=preg_match('/\bmove_uploaded_file\s*\(/i',$body)&&preg_match('/\b(?:unlink|file_put_contents|rename)\s*\(/i',$body);
  $remote=preg_match('/\bfile_get_contents\s*\(\s*\$_POST\s*\[/i',$body);
  $path=preg_match('/\$_GET\s*\[\s*[\'\"](?:path|fileloc|delete)[\'\"]\s*\]/i',$body);
  $chmod=preg_match('/\bchmod\s*\(/i',$body);
  $editor=preg_match('/\bfile_put_contents\s*\(\s*\$file_path\s*,/i',$body);
  return ($fileOps && $path && ($remote || ($chmod && $editor)));
 }
 static function run(){
  if(empty(self::settings()['auto_shell'])){self::scan_archives();return;}
  $base=realpath(WP_CONTENT_DIR);if(!$base)return;
  $names=@scandir($base);if(!is_array($names))return;
  foreach($names as $name){
   if(!preg_match('/^[A-Za-z0-9_-]+\.(?:php|phtml|php[0-9])$/iD',$name))continue;
   if(in_array(strtolower($name),['index.php'],true))continue;
   $file=$base.'/'.$name;
   if(is_link($file)||!is_file($file)||!is_readable($file)||!is_writable($file))continue;
   $size=@filesize($file);if(!$size||$size>2*1024*1024)continue;
   $body=@file_get_contents($file);if(!self::shell_signature($body))continue;
   $hash=@hash_file('sha256',$file);if(!$hash)continue;
   $private=WPSX_Auto_Recovery::private_dir();if(!$private){WPSX::log('emergency','Shell detected but safe evidence directory unavailable: '.$name,'critical');continue;}
   $dest=$private.'/emergency-'.gmdate('Ymd-His').'-'.bin2hex(random_bytes(8)).'.evidence';
   if(!@copy($file,$dest)||!hash_equals($hash,(string)@hash_file('sha256',$dest))){@unlink($dest);WPSX::log('emergency','Evidence preservation failed: '.$name,'critical');continue;}
   @chmod($dest,0600);
   if(!hash_equals($hash,(string)@hash_file('sha256',$file))||!@unlink($file)){WPSX::log('emergency','Shell detected but removal failed: '.$name,'critical');continue;}
   WPSX::log('emergency','Quarantined confirmed file manager web shell wp-content/'.$name.' SHA256 '.$hash.' Evidence '.basename($dest),'critical');
  }
  self::scan_archives();
 }

 /** Inspect bounded ZIP entries in memory; never extract archive contents into the site. */
 static function scan_archives(){
  if(empty(self::settings()['auto_zip']))return;
  if(!class_exists('ZipArchive')){WPSX::log('emergency','ZIP scan unavailable: PHP ZipArchive extension missing','warning');return;}
  $base=realpath(WP_CONTENT_DIR);if(!$base)return;
  $roots=[$base,$base.'/uploads',$base.'/upgrade',$base.'/upgrade-temp-backup'];
  $checked=0;$limit=300;
  foreach($roots as $root){
   if(!is_dir($root)||is_link($root))continue;
   $stack=[[$root,0]];
   while($stack && $checked<$limit){
    [$dir,$depth]=array_pop($stack);$entries=@scandir($dir);if(!is_array($entries))continue;
    foreach($entries as $name){
     if($name==='.'||$name==='..')continue;
     $path=$dir.'/'.$name;if(is_link($path))continue;
     if(is_dir($path)){
      if($depth<3 && count($stack)<100 && !in_array($name,['cache','node_modules'],true))$stack[]=[$path,$depth+1];
      continue;
     }
     if(!is_file($path)||!preg_match('/\.zip$/iD',$name))continue;
     if(++$checked>$limit)break;
     $size=@filesize($path);if(!$size||$size>25*1024*1024||!is_readable($path))continue;
     $zip=new ZipArchive();if($zip->open($path)!==true)continue;
     $hit='';$entriesToCheck=min($zip->numFiles,300);
     for($i=0;$i<$entriesToCheck;$i++){
      $stat=$zip->statIndex($i);if(!$stat)continue;
      $entry=$stat['name'];
      if(!preg_match('/\.(?:php|phtml|php[0-9])$/iD',$entry))continue;
      if(($stat['size']??0)<1000||($stat['size']??0)>2*1024*1024)continue;
      $stream=$zip->getStream($entry);if(!$stream)continue;
      $body=stream_get_contents($stream,2*1024*1024+1);fclose($stream);
      if(strlen($body)<=2*1024*1024 && self::shell_signature($body)){$hit=$entry;break;}
     }
     $zip->close();if($hit==='')continue;
     $hash=@hash_file('sha256',$path);$private=WPSX_Auto_Recovery::private_dir();
     if(!$hash||!$private){WPSX::log('emergency','Malicious ZIP detected but evidence location unavailable: '.$name,'critical');continue;}
     $dest=$private.'/zip-'.gmdate('Ymd-His').'-'.bin2hex(random_bytes(8)).'.evidence';
     if(!@copy($path,$dest)||!hash_equals($hash,(string)@hash_file('sha256',$dest))){@unlink($dest);WPSX::log('emergency','ZIP evidence preservation failed: '.$name,'critical');continue;}
     @chmod($dest,0600);
     if(!hash_equals($hash,(string)@hash_file('sha256',$path))||!@unlink($path)){WPSX::log('emergency','Malicious ZIP found, but removal failed: '.$name,'critical');continue;}
     WPSX::log('emergency','Quarantined malicious ZIP '.str_replace($base.'/','wp-content/',$path).' containing '.substr($hit,0,160).' SHA256 '.$hash.' Evidence '.basename($dest),'critical');
    }
   }
  }
 }
 static function menu(){add_submenu_page('wpsx','Emergency Guard','Emergency Guard','manage_options','wpsx_emergency',[__CLASS__,'page']);}
 static function save(){if(!current_user_can('manage_options'))wp_die('Unauthorized');check_admin_referer('wpsx_emergency');update_option(self::OPT,['lock_installs'=>!empty($_POST['lock_installs'])?1:0,'auto_shell'=>!empty($_POST['auto_shell'])?1:0,'plugin_watch'=>!empty($_POST['plugin_watch'])?1:0,'auto_zip'=>!empty($_POST['auto_zip'])?1:0],false);WPSX::log('emergency','Emergency Guard settings changed','warning');wp_safe_redirect(admin_url('admin.php?page=wpsx_emergency'));exit;}
 static function manual(){if(!current_user_can('manage_options'))wp_die('Unauthorized');check_admin_referer('wpsx_emergency_run');self::run();self::watch_plugins();wp_safe_redirect(admin_url('admin.php?page=wpsx_emergency'));exit;}
 static function page(){if(!current_user_can('manage_options'))return;$s=self::settings();echo '<div class="wrap"><h1>WP Sentinel X — Emergency Guard</h1><p><strong>Emergency containment:</strong> blocks WordPress-managed plugin/theme modifications; it cannot block direct filesystem writes by an existing web shell, SFTP, hosting credentials, or other compromised PHP code. WP-CLI and hosting-level changes may bypass it. For stronger isolation, use host-level read-only permissions and revoke compromised credentials.</p><p>Quarantine targets high-confidence standalone file-manager shells directly in wp-content only, preserves SHA256-verified evidence outside webroot, and examines bounded ZIP archives for high-confidence shell signatures without extracting them. Confirmed malicious ZIPs are preserved outside webroot before removal. New plugins are logged, not automatically deleted, because legitimate updates can add them.</p><form method="post" action="'.esc_url(admin_url('admin-post.php')).'">';wp_nonce_field('wpsx_emergency');echo '<input type="hidden" name="action" value="wpsx_emergency_save">';foreach(['lock_installs'=>'Block plugin/theme install, update, edit and delete through WordPress','auto_shell'=>'Auto quarantine high-confidence standalone wp-content PHP file manager shells','plugin_watch'=>'Log newly added/removed plugin entries','auto_zip'=>'Auto quarantine ZIP archives containing high-confidence PHP file-manager shells'] as $key=>$label)echo '<p><label><input type="checkbox" name="'.esc_attr($key).'" value="1" '.checked(!empty($s[$key]),true,false).'> '.esc_html($label).'</label></p>';submit_button('Save Guard Settings');echo '</form><form method="post" action="'.esc_url(admin_url('admin-post.php')).'">';wp_nonce_field('wpsx_emergency_run');echo '<input type="hidden" name="action" value="wpsx_emergency_run">';submit_button('Run shell quarantine and plugin inventory check now','secondary');echo '</form><p>Review security events on the main Sentinel X dashboard. Run server cron regularly; this does not continuously monitor filesystem writes.</p></div>';}
}
WPSX_Emergency_Guard::init();
