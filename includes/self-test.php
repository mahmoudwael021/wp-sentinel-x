<?php
if (!defined('ABSPATH')) exit;
/** Non-destructive, scheduled health checks. Never creates executable files. */
final class WPSX_Self_Test {
 const CRON='wpsx_self_test_daily'; const LAST='wpsx_self_test_last';
 static function init(){
  add_action('init',[__CLASS__,'schedule']);
  add_action(self::CRON,[__CLASS__,'run']);
  add_action('admin_menu',function(){add_submenu_page('wpsx','Automatic Self-Test','Automatic Self-Test','manage_options','wpsx_self_test',[__CLASS__,'page']);},70);
  add_action('admin_post_wpsx_self_test', [__CLASS__,'manual']);
 }
 static function schedule(){if(!wp_next_scheduled(self::CRON))wp_schedule_event(time()+600,'daily',self::CRON);}
 static function check($ok,$message){return ['status'=>$ok?'pass':'fail','detail'=>$message];}
 static function run(){
  $results=[];
  $results['wp_cron']=self::check((bool)wp_next_scheduled(WPSX_Auto_Recovery::CRON),'Auto Recovery scheduled in WP-Cron (does not prove server cron executes)');
  $results['persistence_cron']=self::check((bool)wp_next_scheduled(WPSX_Persistence_Monitor::HOOK),'Persistence monitoring scheduling (verify actual hook if failed)');
  $results['recovery_enabled']=self::check(!empty(WPSX_Auto_Recovery::settings()['enabled']),'Auto Recovery opt-in enabled');
  $private=WPSX_Auto_Recovery::private_dir();
  $results['evidence_directory']=self::check((bool)$private && is_writable($private),'Private evidence directory exists outside web root and is writable');
  // Use a harmless temporary text file in the evidence directory; do not execute or quarantine real files.
  $ok=false;
  if($private){
   $name=$private.'/selftest-'.wp_generate_uuid4().'.txt';
   $payload='WPSX SELF TEST '.wp_generate_uuid4();
   if(@file_put_contents($name,$payload,LOCK_EX)===strlen($payload)){
    @chmod($name,0600);
    $ok=hash_equals(hash('sha256',$payload),(string)@hash_file('sha256',$name));
   }
   if(is_file($name) && !@unlink($name))$ok=false;
  }
  $results['evidence_roundtrip']=self::check($ok,'Safe non-executable text write, SHA-256 verification and cleanup');
  $p=get_option('wpsx_persistence_monitor_last',[]);
  $last_complete=(int)get_option('wpsx_persistence_monitor_last_complete',0);
  if(is_array($p) && !empty($p['complete']))$results['persistence_inventory']=self::check(true,'Latest inventory completed; this does not prove a clean site');
  elseif(is_array($p) && !empty($p['remaining']) && $last_complete && time()-$last_complete<DAY_IN_SECONDS)$results['persistence_inventory']=['status'=>'in_progress','detail'=>'New inventory in progress; previous complete scan '.gmdate('Y-m-d H:i:s',$last_complete).' UTC'];
  else $results['persistence_inventory']=self::check(false,'No recent completed inventory; check scheduling, errors and progress');
  $results['critical_files_cron']=self::check((bool)wp_next_scheduled(WPSX_Critical_Files::HOOK),'Critical-file integrity check scheduled');
  $fail=count(array_filter($results,static function($r){return $r['status']==='fail';}));
  $pending=count(array_filter($results,static function($r){return $r['status']==='in_progress';}));
  $report=['time'=>time(),'results'=>$results,'passed'=>count($results)-$fail-$pending,'failed'=>$fail,'pending'=>$pending];
  update_option(self::LAST,$report,false);
  if($fail)WPSX::log('self_test',$fail.' self-test check(s) need attention','critical');
  return $report;
 }
 static function manual(){if(!current_user_can('manage_options'))wp_die('Unauthorized',403);check_admin_referer('wpsx_self_test');self::run();wp_safe_redirect(admin_url('admin.php?page=wpsx_self_test'));exit;}
 static function page(){
  if(!current_user_can('manage_options'))return;
  $r=get_option(self::LAST,[]);
  echo '<div class="wrap"><h1>WP Sentinel X — Automatic Self-Test</h1><p>Daily, non-destructive health checks. This tests scheduling configuration and evidence write/verify/cleanup; it does not prove malware detection accuracy, email delivery, actual server-cron execution or site cleanliness.</p>';
  echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'">';wp_nonce_field('wpsx_self_test');echo '<input type="hidden" name="action" value="wpsx_self_test">';submit_button('Run safe self-test now');echo '</form>';
  if(!is_array($r)||empty($r['time'])){echo '<p>No self-test results yet.</p></div>';return;}
  echo '<p><strong>Last test:</strong> '.esc_html(gmdate('Y-m-d H:i:s',(int)$r['time'])).' UTC | Passed: '.intval($r['passed']).' | In progress: '.intval($r['pending']??0).' | Needs attention: '.intval($r['failed']).'</p>';
  echo '<table class="widefat striped"><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody>';
  foreach($r['results'] as $name=>$result)echo '<tr><td>'.esc_html(str_replace('_',' ',ucwords($name,'_'))).'</td><td>'.esc_html($result['status']).'</td><td>'.esc_html($result['detail']).'</td></tr>';
  echo '</tbody></table><p>Automatic recovery remains restricted to previously configured high-confidence cases. Never auto-delete all new PHP files: legitimate plugin files can be created during updates.</p></div>';
 }
}
WPSX_Self_Test::init();
