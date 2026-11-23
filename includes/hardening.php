<?php
if (!defined('ABSPATH')) exit;
/** Defensive, opt-in file protection. Server-level policy is required for robust prevention. */
final class WPSX_Hardening {
 const STATE='wpsx_hardening_state';
 static function init(){
  add_action('admin_menu',function(){add_submenu_page('wpsx','File Protection','File Protection','manage_options','wpsx_file_protection',[__CLASS__,'page']);},35);
  add_action('admin_post_wpsx_hardening',[__CLASS__,'handle']);
  add_action(WPSX::CRON,[__CLASS__,'monitor'],20);
 }
 static function root_index(){return ABSPATH.'index.php';}
 static function state(){ $v=get_option(self::STATE,[]);return is_array($v)?$v:[]; }
 static function fingerprint(){ $p=self::root_index();return is_file($p)&&!is_link($p)?@hash_file('sha256',$p):false; }
 static function monitor(){
  $state=self::state();$now=self::fingerprint();
  if(!$now){WPSX::log('root_index','Root index.php missing or unreadable','critical');return;}
  if(empty($state['index_hash'])){ $state['index_hash']=$now;$state['checked']=time();update_option(self::STATE,$state,false);return; }
  if(!hash_equals($state['index_hash'],$now)){
   $key='wpsx_index_change_'.substr($now,0,24);
   if(!get_transient($key)){WPSX::log('root_index','ALERT: root index.php changed. Review and use verified core repair; current sha256 '.$now,'critical');set_transient($key,1,DAY_IN_SECONDS);}
  }
  $state['checked']=time();update_option(self::STATE,$state,false);
 }
 static function allowed_dir($dir){$real=realpath($dir);$content=realpath(WP_CONTENT_DIR);return $real&&$content&&$real!==$content&&strpos($real,$content.DIRECTORY_SEPARATOR)===0&&!is_link($dir);}
 static function guard_targets(){
  $dirs=[];$uploads=wp_upload_dir();if(empty($uploads['error'])&&!empty($uploads['basedir']))$dirs[]=$uploads['basedir'];
  foreach(['upgrade','cache','backups','backup','ai1wm-backups'] as $name){$p=WP_CONTENT_DIR.'/'.$name;if(is_dir($p))$dirs[]=$p;}
  return array_unique($dirs);
 }
 static function install_guards(){
  $ok=[];$fail=[];
  $block="\n# BEGIN WPSX EXECUTION GUARD\n<FilesMatch \"\\.(?:php[0-9]?|phtml|phar|cgi|pl|py|sh)$\">\nRequire all denied\n</FilesMatch>\n<FilesMatch \"^(?:\\.user\\.ini|\\.htaccess)$\">\nRequire all denied\n</FilesMatch>\n# END WPSX EXECUTION GUARD\n";
  foreach(self::guard_targets() as $dir){
   if(!self::allowed_dir($dir)||!is_writable($dir)){$fail[]=$dir.' (unwritable/unsafe)';continue;}
   $p=rtrim($dir,'/').'/.htaccess';if(is_link($p)){$fail[]=$p.' (symlink)';continue;}
   $old=is_file($p)?@file_get_contents($p):'';
   if(!is_string($old)||strlen($old)>1024*1024){$fail[]=$p.' (unreadable/too large)';continue;}
   if(strpos($old,'# BEGIN WPSX EXECUTION GUARD')!==false){$ok[]=$dir.' (already present)';continue;}
   // Never overwrite existing rules. Abort if backup cannot be preserved.
   if(is_file($p)){
    $backup=dirname(realpath(ABSPATH)).'/wpsx-private/htaccess-'.hash('sha256',$p).'-'.gmdate('YmdHis').'.bak';
    WPSX::private_dir();if(!is_dir(dirname($backup))||!@copy($p,$backup)){$fail[]=$p.' (backup failed)';continue;}
    @chmod($backup,0600);
   }
   if(@file_put_contents($p,$old.$block,LOCK_EX)===false){$fail[]=$p.' (write failed)';continue;}
   $ok[]=$dir;
  }
  WPSX::log('hardening','Apache guards: '.count($ok).' installed/existing, '.count($fail).' failures',count($fail)?'warning':'info');
  return ['ok'=>$ok,'fail'=>$fail];
 }
 static function handle(){
  if(!current_user_can('manage_options'))wp_die('Unauthorized',403);
  check_admin_referer('wpsx_hardening');
  $action=isset($_POST['operation'])?sanitize_key(wp_unslash($_POST['operation'])):'';
  $notice='No action performed.';
  if($action==='baseline'){
   $hash=self::fingerprint();if($hash){$s=self::state();$s['index_hash']=$hash;$s['checked']=time();update_option(self::STATE,$s,false);$notice='Root index.php fingerprint saved. This is monitoring, not malware validation.';WPSX::log('root_index','Root index.php baseline approved by administrator','warning');}
  }elseif($action==='guards'){
   $r=self::install_guards();$notice='Apache guards installed/existing: '.count($r['ok']).'; failed: '.count($r['fail']).'. Verify your web server uses Apache/LiteSpeed and inspect failures.';
  }elseif($action==='lock'||$action==='unlock'){
   $p=self::root_index();if(is_file($p)&&!is_link($p)){
    $mode=$action==='lock'?0444:0644;
    if(@chmod($p,$mode)){$notice='index.php permissions set to '.decoct($mode).'. Owner/server processes may still change permissions. WordPress updates may require unlocking.';WPSX::log('root_index','Permissions changed to '.decoct($mode),'warning');}
    else $notice='Could not change index.php permissions; hosting policy may prevent this.';
   }
  }
  set_transient('wpsx_hardening_notice_'.get_current_user_id(),$notice,120);
  wp_safe_redirect(admin_url('admin.php?page=wpsx_file_protection'));exit;
 }
 static function button($action,$label){echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'" style="display:inline-block;margin:5px 8px 5px 0">';wp_nonce_field('wpsx_hardening');echo '<input type="hidden" name="action" value="wpsx_hardening"><input type="hidden" name="operation" value="'.esc_attr($action).'">';submit_button($label,'secondary','submit',false);echo '</form>';}
 static function page(){
  if(!current_user_can('manage_options'))return;
  $s=self::state();$hash=self::fingerprint();$changed=(!empty($s['index_hash'])&&$hash&&!hash_equals($s['index_hash'],$hash));
  $notice=get_transient('wpsx_hardening_notice_'.get_current_user_id());
  echo '<div class="wrap"><h1>WP Sentinel X — File Protection v0.5.8</h1>';
  if($notice){echo '<div class="notice notice-info"><p>'.esc_html($notice).'</p></div>';delete_transient('wpsx_hardening_notice_'.get_current_user_id());}
  echo '<p><strong>Important:</strong> A WordPress plugin cannot make PHP files immutable against an attacker with hosting/FTP/root access. Apache rules do not work on Nginx unless the host configures equivalent restrictions. Keep independent backups.</p>';
  echo '<h2>Root index.php</h2><p>Path: <code>'.esc_html(self::root_index()).'</code></p><p>SHA-256: <code>'.esc_html($hash?:'unavailable').'</code></p><p>Baseline: <code>'.esc_html($s['index_hash']??'not set').'</code></p>';
  echo '<p><strong>Status: '.($changed?'<span style="color:#b32d2e">CHANGED — inspect before approving</span>':(!empty($s['index_hash'])?'Unchanged since baseline':'Not monitored yet')).'</strong></p>';
  echo '<p>Hourly WP-Cron monitoring sends an alert on change. It does not silently restore an infected file. For core repair use the verified core repair action on the Sentinel X dashboard after backup.</p>';
  self::button('baseline','Approve current index.php fingerprint');
  echo '<p><strong>Optional permissions:</strong> Read-only (444) may reduce accidental changes but is not a security boundary and may block updates. Never enable without a working backup and recovery access.</p>';
  self::button('lock','Set index.php read-only (444)');self::button('unlock','Allow updates (644)');
  echo '<h2>Writable directories: PHP execution guard</h2><p>Installs a non-destructive Apache/LiteSpeed .htaccess rule for uploads and existing cache/backup/upgrade folders. Existing .htaccess files are backed up outside public_html before changes. PHP uploads through WordPress are already blocked by the plugin prefilter, but direct FTP/SFTP writes bypass that filter.</p>';
  echo '<p>Targets: '.esc_html(implode(', ',self::guard_targets())).'</p>';
  self::button('guards','Install / update Apache guards');
  echo '<h2>Server protection still required</h2><p>Ask Hostinger to disable PHP execution in uploads/cache, disable FTP in favor of SFTP, review cron jobs and credentials, and enable server WAF and offsite backups. Keep Wordfence enabled; avoid overlapping login/firewall policies.</p></div>';
 }
}
WPSX_Hardening::init();
