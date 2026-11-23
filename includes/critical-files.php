<?php
if (!defined('ABSPATH')) exit;
/** Critical-file integrity monitoring. Never rewrites configuration or accepts changed hashes. */
final class WPSX_Critical_Files {
 const HOOK='wpsx_critical_files_15m';
 const BASE='wpsx_critical_files_baseline';
 const LAST='wpsx_critical_files_last';
 static function init(){
  add_filter('cron_schedules',[__CLASS__,'intervals']);
  add_action('init',[__CLASS__,'schedule']);
  add_action(self::HOOK,[__CLASS__,'run']);
  add_action('admin_menu',function(){add_submenu_page('wpsx','Critical File Integrity','Critical File Integrity','manage_options','wpsx_critical_files',[__CLASS__,'page']);},48);
  add_action('admin_post_wpsx_critical_check',[__CLASS__,'manual']);
 }
 static function intervals($s){$s['wpsx_critical_15m']=['interval'=>900,'display'=>'Every 15 minutes (critical file integrity)'];return $s;}
 static function schedule(){if(!wp_next_scheduled(self::HOOK))wp_schedule_event(time()+300,'wpsx_critical_15m',self::HOOK);}
 static function paths(){
  $root=rtrim(ABSPATH,'/\\').DIRECTORY_SEPARATOR;
  $items=['wp-config.php'=>$root.'wp-config.php','.htaccess'=>$root.'.htaccess','.user.ini'=>$root.'.user.ini','index.php'=>$root.'index.php','wp-load.php'=>$root.'wp-load.php','wp-settings.php'=>$root.'wp-settings.php','wp-blog-header.php'=>$root.'wp-blog-header.php','wp-content/advanced-cache.php'=>WP_CONTENT_DIR.'/advanced-cache.php','wp-content/object-cache.php'=>WP_CONTENT_DIR.'/object-cache.php','wp-content/db.php'=>WP_CONTENT_DIR.'/db.php'];
  $parent=dirname($root);$outside=$parent.'/wp-config.php';
  if(is_file($outside) && realpath($outside)!==realpath($items['wp-config.php']))$items['wp-config.php (parent)']=$outside;
  return $items;
 }
 static function state(){
  $out=[];
  foreach(self::paths() as $name=>$path){
   if(is_link($path)){$out[$name]='SYMLINK';continue;}
   if(!file_exists($path)){$out[$name]='ABSENT';continue;}
   if(!is_file($path)||!is_readable($path)){$out[$name]='UNREADABLE';continue;}
   $hash=@hash_file('sha256',$path);$out[$name]=$hash?:'UNREADABLE';
  }
  return $out;
 }
 static function run(){
  $now=self::state();$base=get_option(self::BASE,[]);$changed=[];
  if(!is_array($base)||!$base){
   update_option(self::BASE,$now,false);
   WPSX::log('critical_files','Initial UNTRUSTED critical-file fingerprint captured; investigate before trusting','warning');
  }else{
   foreach($now as $name=>$hash){
    $old=$base[$name]??'ABSENT';
    if($old===$hash)continue;
    $changed[]=$name;
    $key='wpsx_critical_alert_'.substr(hash('sha256',$name.'|'.$hash),0,24);
    if(!get_transient($key)){
     WPSX::log('critical_files','Critical file changed: '.$name.' (current fingerprint '.$hash.'). No automatic overwrite.','critical');
     set_transient($key,1,DAY_IN_SECONDS);
    }
   }
  }
  update_option(self::LAST,['time'=>time(),'changes'=>$changed,'current'=>$now],false);
 }
 static function manual(){if(!current_user_can('manage_options'))wp_die('Forbidden',403);check_admin_referer('wpsx_critical_check');self::run();wp_safe_redirect(admin_url('admin.php?page=wpsx_critical_files'));exit;}
 static function page(){
  if(!current_user_can('manage_options'))return;
  $base=get_option(self::BASE,[]);$last=get_option(self::LAST,[]);$now=self::state();
  echo '<div class="wrap"><h1>WP Sentinel X — Critical File Integrity</h1><p>Monitors configuration and bootstrapping files every 15 minutes. The first fingerprints are untrusted observations, not proof of clean files. A PHP plugin cannot stop an attacker with filesystem access from changing files. No automatic rewriting or chmod is performed.</p>';
  echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'">';wp_nonce_field('wpsx_critical_check');echo '<input type="hidden" name="action" value="wpsx_critical_check">';submit_button('Check critical files now');echo '</form>';
  echo '<p><strong>Last check:</strong> '.(!empty($last['time'])?esc_html(gmdate('Y-m-d H:i:s',(int)$last['time']).' UTC'):'Never').' | <strong>Changes from initial fingerprints:</strong> '.count((array)($last['changes']??[])).'</p>';
  echo '<table class="widefat striped"><thead><tr><th>File</th><th>Status</th><th>SHA-256 / state</th></tr></thead><tbody>';
  foreach($now as $name=>$hash){$old=$base[$name]??'ABSENT';$status=empty($base)?'No baseline':($old===$hash?'Unchanged':'CHANGED — review');echo '<tr><td>'.esc_html($name).'</td><td>'.esc_html($status).'</td><td><code>'.esc_html($hash).'</code></td></tr>';}
  echo '</tbody></table><p>For stronger protection, keep hosting credentials secure, disable the WordPress file editor, restrict filesystem access, and use verified offsite backups. WordPress/plugin updates can legitimately change some of these files.</p></div>';
 }
}
WPSX_Critical_Files::init();
