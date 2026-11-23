<?php
if (!defined('ABSPATH')) exit;
/** Bounded, read-only persistence change detector. No automatic baseline acceptance. */
final class WPSX_Persistence_Monitor {
 const HOOK='wpsx_persistence_monitor_15m';
 const BASE='wpsx_persistence_monitor_baseline';
 const LAST='wpsx_persistence_monitor_last';
 const EVENTS='wpsx_persistence_monitor_events';
 const LOCK='wpsx_persistence_monitor_lock';
 const PROGRESS='wpsx_persistence_monitor_progress';
 const BATCH_ENTRIES=1800;
 static function init(){
  add_action('init',[__CLASS__,'schedule']);
  add_action(self::HOOK,[__CLASS__,'run']);
  add_action('admin_menu',[__CLASS__,'menu'],46);
  add_action('admin_post_wpsx_pm_scan',[__CLASS__,'manual']);
  add_action('admin_post_wpsx_pm_baseline',[__CLASS__,'baseline']);
 }
 static function schedule(){
  if(!wp_next_scheduled(self::HOOK))wp_schedule_event(time()+300,'wpsx_pm_fifteen',self::HOOK);
 }
 static function intervals($s){$s['wpsx_pm_fifteen']=['interval'=>900,'display'=>'Every 15 minutes (Sentinel X persistence)'];return $s;}
 static function menu(){add_submenu_page('wpsx','Persistence Monitoring','Persistence Monitoring','manage_options','wpsx_persistence_monitor',[__CLASS__,'page']);}
 /** Resumable directory inventory. Each invocation examines at most BATCH_ENTRIES entries.
  * A partial inventory is never compared with or promoted to a baseline.
  * No PHP content is executed; only selected files are hashed. */
 static function initial_progress(){
  $files=[];
  foreach(['wp-config.php','.htaccess','.user.ini','index.php','wp-content/advanced-cache.php','wp-content/object-cache.php','wp-content/db.php','wp-content/sunrise.php'] as $p)$files[$p]=null;
  $queue=[];
  foreach(['wp-content/mu-plugins','wp-content/uploads','wp-content/upgrade'] as $dir){
   if(is_dir(ABSPATH.$dir) && !is_link(ABSPATH.$dir))$queue[]=['dir'=>$dir,'offset'=>0];
  }
  return ['queue'=>$queue,'files'=>$files,'processed'=>0,'started'=>time()];
 }
 static function file_hash($rel){
  $p=ABSPATH.$rel;
  if(is_link($p))return 'symlink';
  if(!is_file($p))return 'absent';
  $size=@filesize($p);
  if($size===false)return 'unreadable';
  if($size>4194304)return 'oversized:'.(string)$size;
  $hash=@hash_file('sha256',$p);
  return is_string($hash)?$hash:'unreadable';
 }
 static function snapshot(){
  $state=get_option(self::PROGRESS,[]);
  if(!is_array($state)||!isset($state['queue'],$state['files']))$state=self::initial_progress();
  $start=microtime(true);$used=0;$error='';
  while(!empty($state['queue']) && $used<self::BATCH_ENTRIES && microtime(true)-$start<8){
   $item=array_shift($state['queue']);$dir=$item['dir'];$offset=(int)$item['offset'];
   $root=ABSPATH.$dir;
   if(!is_dir($root)||is_link($root)){ $error='Directory disappeared or became symlink: '.$dir;break; }
   $entries=@scandir($root);
   if(!is_array($entries)){ $error='Cannot read directory: '.$dir;break; }
   $entries=array_values(array_diff($entries,['.','..']));sort($entries,SORT_STRING);
   $count=count($entries);
   while($offset<$count && $used<self::BATCH_ENTRIES && microtime(true)-$start<8){
    $name=$entries[$offset++];$used++;$state['processed']++;
    $rel=$dir.'/'.$name;$path=ABSPATH.$rel;
    if(is_link($path)){
     if(preg_match('/\.(?:php[0-9]?|phtml|phar)$/i',$name))$state['files'][$rel]='symlink';
     continue;
    }
    if(is_dir($path)){$state['queue'][]=['dir'=>$rel,'offset'=>0];continue;}
    if(!is_file($path))continue;
    if(strpos($dir,'wp-content/mu-plugins')===0 || preg_match('/\.(?:php[0-9]?|phtml|phar)$/i',$name) || $name==='.user.ini')$state['files'][$rel]=null;
   }
   if($offset<$count)$state['queue'][]=['dir'=>$dir,'offset'=>$offset];
  }
  if($error){delete_option(self::PROGRESS);return ['complete'=>false,'error'=>$error,'processed'=>(int)$state['processed'],'remaining'=>count($state['queue'])];}
  if(!empty($state['queue'])){
   update_option(self::PROGRESS,$state,false);
   return ['complete'=>false,'partial'=>true,'processed'=>(int)$state['processed'],'remaining'=>count($state['queue']),'error'=>'Inventory in progress; next scheduled run continues'];
  }
  delete_option(self::PROGRESS);
  $files=[];
  foreach($state['files'] as $rel=>$ignored)$files[$rel]=self::file_hash($rel);
  ksort($files);
  $admins=[];
  foreach(get_users(['role'=>'administrator','fields'=>['ID','user_login','user_email','user_registered']]) as $u)$admins[(string)$u->ID]=hash('sha256',$u->user_login.'|'.$u->user_email.'|'.$u->user_registered);
  ksort($admins);
  $cron=[];
  if(function_exists('_get_cron_array'))foreach((array)_get_cron_array() as $hooks)foreach((array)$hooks as $hook=>$events)$cron[$hook]=true;
  ksort($cron);
  $options=['users_can_register'=>(string)get_option('users_can_register'),'default_role'=>(string)get_option('default_role'),'siteurl'=>(string)get_option('siteurl'),'home'=>(string)get_option('home')];
  return ['complete'=>true,'files'=>$files,'admins'=>$admins,'cron'=>array_keys($cron),'options'=>$options,'processed'=>(int)$state['processed'],'remaining'=>0];
 }
 static function changes($old,$new){
  $changes=[];
  foreach(['files'=>'file','admins'=>'administrator','options'=>'option'] as $key=>$label){
   $before=(array)($old[$key]??[]);$after=(array)($new[$key]??[]);
   foreach($after as $id=>$value){if(!array_key_exists($id,$before))$changes[]=['kind'=>$label,'type'=>'added','target'=>(string)$id];elseif($before[$id]!==$value)$changes[]=['kind'=>$label,'type'=>'changed','target'=>(string)$id];}
   foreach($before as $id=>$value)if(!array_key_exists($id,$after))$changes[]=['kind'=>$label,'type'=>'removed','target'=>(string)$id];
  }
  $before=array_fill_keys((array)($old['cron']??[]),true);$after=array_fill_keys((array)($new['cron']??[]),true);
  foreach($after as $hook=>$v)if(!isset($before[$hook]))$changes[]=['kind'=>'cron','type'=>'added','target'=>(string)$hook];
  foreach($before as $hook=>$v)if(!isset($after[$hook]))$changes[]=['kind'=>'cron','type'=>'removed','target'=>(string)$hook];
  return array_slice($changes,0,150);
 }
 static function run(){
  $token=wp_generate_uuid4();
  if(!add_option(self::LOCK,['token'=>$token,'time'=>time()],'','no')){
   $old=get_option(self::LOCK);if(!is_array($old)||time()-(int)($old['time']??0)<180)return;
   delete_option(self::LOCK);if(!add_option(self::LOCK,['token'=>$token,'time'=>time()],'','no'))return;
  }
  try{
   $snapshot=self::snapshot();$base=get_option(self::BASE,[]);$last=['time'=>time(),'complete'=>!empty($snapshot['complete']),'changes'=>0,'error'=>$snapshot['error']??'','processed'=>(int)($snapshot['processed']??0),'remaining'=>(int)($snapshot['remaining']??0)];
   if(empty($snapshot['complete'])){if(empty($snapshot['partial']))WPSX::log('persistence_monitor','Monitoring incomplete: '.$last['error'],'warning');}
   elseif(empty($base['created'])){
    // The first baseline is observational, NOT a trusted clean verdict.
    update_option(self::BASE,['created'=>time(),'data'=>$snapshot],false);
    WPSX::log('persistence_monitor','Initial untrusted persistence snapshot captured. Review before relying on change detection.','warning');
   }else{
    $changes=self::changes((array)($base['data']??[]),$snapshot);$last['changes']=count($changes);
    if($changes){
     $events=get_option(self::EVENTS,[]);if(!is_array($events))$events=[];
     foreach($changes as $change){
      $fingerprint=hash('sha256',implode('|',$change));
      // Suppress duplicate alerts while preserving new changes.
      $seen='wpsx_pm_seen_'.substr($fingerprint,0,24);
      if(get_transient($seen))continue;
      set_transient($seen,1,DAY_IN_SECONDS);
      array_unshift($events,['time'=>time()]+$change);
      WPSX::log('persistence_monitor',strtoupper($change['type']).' '.$change['kind'].': '.$change['target'],'critical');
     }
     update_option(self::EVENTS,array_slice($events,0,250),false);
    }
   }
   if(!empty($snapshot['complete']))update_option('wpsx_persistence_monitor_last_complete',time(),false);
   update_option(self::LAST,$last,false);
  }catch(Throwable $e){update_option(self::LAST,['time'=>time(),'complete'=>false,'changes'=>0,'error'=>substr($e->getMessage(),0,180)],false);WPSX::log('persistence_monitor','Monitor error: '.substr($e->getMessage(),0,180),'warning');}
  finally{$lock=get_option(self::LOCK);if(is_array($lock)&&($lock['token']??'')===$token)delete_option(self::LOCK);}
 }
 static function manual(){if(!current_user_can('manage_options'))wp_die('Forbidden',403);check_admin_referer('wpsx_pm_scan');self::run();wp_safe_redirect(admin_url('admin.php?page=wpsx_persistence_monitor'));exit;}
 static function baseline(){
  if(!current_user_can('manage_options'))wp_die('Forbidden',403);check_admin_referer('wpsx_pm_baseline');
  $snapshot=self::snapshot();if(!empty($snapshot['complete'])){update_option(self::BASE,['created'=>time(),'data'=>$snapshot],false);WPSX::log('persistence_monitor','Administrator explicitly approved a new persistence snapshot','warning');}
  wp_safe_redirect(admin_url('admin.php?page=wpsx_persistence_monitor'));exit;
 }
 static function page(){
  if(!current_user_can('manage_options'))return;
  $base=get_option(self::BASE,[]);$last=get_option(self::LAST,[]);$events=get_option(self::EVENTS,[]);
  echo '<div class="wrap"><h1>WP Sentinel X — Persistence Monitoring v0.6.5</h1>';
  echo '<p><strong>Read-only, every 15 minutes:</strong> watches critical configuration files, PHP in uploads/upgrade, mu-plugins, administrator accounts, option changes and WP-Cron hook names. This cannot identify the attacker or block writes. First snapshot may already be compromised. No automatic quarantine. An initial complete snapshot is observational and untrusted; do not approve it as clean without investigation.</p>';
  echo '<p><strong>Baseline:</strong> '.(!empty($base['created'])?esc_html(gmdate('Y-m-d H:i:s',(int)$base['created']).' UTC'):'Not yet established').' | <strong>Last check:</strong> '.(!empty($last['time'])?esc_html(gmdate('Y-m-d H:i:s',(int)$last['time']).' UTC'):'Never').' | <strong>Complete:</strong> '.(!empty($last['complete'])?'Yes':'No').' | <strong>Changes:</strong> '.intval($last['changes']??0).' | <strong>Entries traversed:</strong> '.intval($last['processed']??0).' | <strong>Pending directories:</strong> '.intval($last['remaining']??0).'</p>';
  if(!empty($last['remaining']))echo '<p><strong>Inventory is progressing in batches.</strong> It will continue on the next scheduled run. Do not approve a baseline until a full scan completes and the site is reviewed.</p>';
  if(!empty($last['error']))echo '<div class="notice notice-warning"><p>'.esc_html($last['error']).'</p></div>';
  echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'">';wp_nonce_field('wpsx_pm_scan');echo '<input type="hidden" name="action" value="wpsx_pm_scan">';submit_button('Run read-only persistence check');echo '</form>';
  echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'" onsubmit="return confirm(\'Only approve after verifying the current site is clean. Replace monitoring baseline?\');">';wp_nonce_field('wpsx_pm_baseline');echo '<input type="hidden" name="action" value="wpsx_pm_baseline">';submit_button('Approve current snapshot as new baseline','secondary');echo '</form>';
  echo '<h2>Recent changes</h2><table class="widefat striped"><thead><tr><th>UTC</th><th>Category</th><th>Change</th><th>Target</th></tr></thead><tbody>';
  foreach(array_slice((array)$events,0,50) as $e)echo '<tr><td>'.esc_html(gmdate('Y-m-d H:i:s',(int)($e['time']??0))).'</td><td>'.esc_html($e['kind']??'').'</td><td>'.esc_html($e['type']??'').'</td><td><code>'.esc_html($e['target']??'').'</code></td></tr>';
  if(!$events)echo '<tr><td colspan="4">No recorded changes. This does not establish a clean site.</td></tr>';
  echo '</tbody></table><p>Events are capped at 250; first 50 displayed. Investigate unexpected changes immediately and rotate credentials. Server-level logs are needed to attribute who wrote a file.</p></div>';
 }
}
add_filter('cron_schedules',['WPSX_Persistence_Monitor','intervals']);
WPSX_Persistence_Monitor::init();
