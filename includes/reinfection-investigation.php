<?php
if (!defined('ABSPATH')) exit;
/** Read-only persistence investigation; no attribution without host audit logs. */
final class WPSX_Reinfection_Investigation {
 const EVENTS='wpsx_reinfection_events'; const STATE='wpsx_reinfection_mu_state'; const LAST='wpsx_reinfection_last';
 static function init(){
  add_action('admin_menu',function(){add_submenu_page('wpsx','Reinfection Investigation','Reinfection Investigation','manage_options','wpsx_reinfection',[__CLASS__,'page']);},41);
  add_action('admin_post_wpsx_reinfection_scan',[__CLASS__,'manual_scan']);
 }
 static function manual_scan(){
  if(!current_user_can('manage_options'))wp_die('Insufficient permissions');
  check_admin_referer('wpsx_reinfection_scan');
  $root=realpath(ABSPATH);
  if($root)self::scan_candidates($root);
  else update_option(self::LAST,['time'=>time(),'files'=>0,'partial'=>true,'hits'=>[],'error'=>'ABSPATH could not be resolved','directories'=>[]],false);
  wp_safe_redirect(admin_url('admin.php?page=wpsx_reinfection&scan=done'));exit;
 }
 static function event($type,$path,$detail){$events=get_option(self::EVENTS,[]);if(!is_array($events))$events=[];array_unshift($events,['time'=>time(),'type'=>$type,'path'=>$path,'detail'=>$detail]);update_option(self::EVENTS,array_slice($events,0,150),false);}
 static function inspect(){
  $root=realpath(ABSPATH);if(!$root)return;
  $dir=$root.'/wp-content/mu-plugins';$prior=get_option(self::STATE,[]);if(!is_array($prior))$prior=[];
  $current=[];$names=is_dir($dir)&&!is_link($dir)?@scandir($dir):[];
  if(is_array($names))foreach($names as $name){
   if(!preg_match('/^[A-Za-z0-9._-]+\.php$/D',$name))continue;
   $path=$dir.'/'.$name;$real=realpath($path);if(!$real||dirname($real)!==realpath($dir)||is_link($path)||!is_file($path))continue;
   $size=@filesize($path);if($size===false||$size>4*1024*1024)continue;
   $hash=@hash_file('sha256',$path);if(!$hash)continue;
   $current[$name]=['hash'=>$hash,'mtime'=>(int)@filemtime($path),'size'=>$size];
   if(!isset($prior[$name]))self::event('created_observed','wp-content/mu-plugins/'.$name,'First observed; SHA256 '.$hash.'; file mtime '.gmdate('c',(int)@filemtime($path)).' (mtime is not proof of creation time)');
   elseif(($prior[$name]['hash']??'')!==$hash)self::event('modified_observed','wp-content/mu-plugins/'.$name,'SHA256 changed from '.$prior[$name]['hash'].' to '.$hash);
  }
  foreach($prior as $name=>$meta)if(!isset($current[$name]))self::event('missing_observed','wp-content/mu-plugins/'.$name,'Previously observed file is absent; may have been quarantined');
  update_option(self::STATE,$current,false);
  self::scan_candidates($root);
 }
 static function quarantined($relative,$hash){self::event('quarantined',$relative,'Confirmed automatic quarantine; SHA256 '.$hash.'. Source process not identified.');}
 static function scan_candidates($root){
  // Read-only, bounded, and diagnostic. Never follow symlinks or execute content.
  $dirs=['wp-content/mu-plugins','wp-content/plugins','wp-content/themes','wp-content/uploads','wp-content/upgrade'];
  $hits=[];$files=0;$limit=600;$deadline=microtime(true)+8.0;
  $partial=false;$report=[];$errors=[];$seen=[];
  foreach($dirs as $rel){
   $base=$root.'/'.$rel;
   $r=['directory'=>$rel,'status'=>'pending','files'=>0,'skipped'=>0,'errors'=>0,'directories'=>0];
   if(!is_dir($base)){$r['status']='missing';$report[]=$r;continue;}
   if(is_link($base)){$r['status']='symlink skipped';$r['skipped']++;$report[]=$r;continue;}
   if(!is_readable($base)){$r['status']='unreadable';$r['errors']++;$errors[]=$rel.': not readable';$report[]=$r;continue;}
   if($files>=$limit||microtime(true)>=$deadline){$r['status']='not reached (limit)';$partial=true;$report[]=$r;continue;}
   $queue=[$base];$visited=0;$r['status']='completed';
   while($queue){
    if($files>=$limit||microtime(true)>=$deadline||$visited>=400){$partial=true;$r['status']='partial (limit)';break;}
    $dir=array_shift($queue);$real=realpath($dir);
    if(!$real||($real!==realpath($base)&&strpos($real,realpath($base).DIRECTORY_SEPARATOR)!==0)){$r['skipped']++;continue;}
    if(isset($seen[$real]))continue;$seen[$real]=true;
    $visited++;$r['directories']++;
    $items=@scandir($dir);
    if(!is_array($items)){$r['errors']++;$errors[]=$rel.': cannot list '.substr($dir,strlen($root)+1);continue;}
    foreach($items as $name){
     if($name==='.'||$name==='..')continue;
     if($files>=$limit||microtime(true)>$deadline){$partial=true;$r['status']='partial (limit)';break;}
     $path=$dir.'/'.$name;
     if(is_link($path)){$r['skipped']++;continue;}
     if(is_dir($path)){$queue[]=$path;continue;}
     if(!is_file($path)||!preg_match('/\.(?:php[0-9]?|phtml|inc)$/i',$name))continue;
     $files++;$r['files']++;
     $size=@filesize($path);
     if($size===false||$size<20||$size>1024*1024){$r['skipped']++;continue;}
     if(!is_readable($path)){$r['errors']++;$errors[]='Cannot read '.substr($path,strlen($root)+1);continue;}
     $body=@file_get_contents($path,false,null,0,1024*1024);
     if(!is_string($body)){$r['errors']++;$errors[]='Read failed '.substr($path,strlen($root)+1);continue;}
     $signals=[];
     if(preg_match('/(?:mu-plugins[\x27\x22\s.\/\\\\]*index\.php|mu-plugins.{0,100}file_put_contents|file_put_contents.{0,160}mu-plugins)/is',$body))$signals[]='references MU index/write';
     if(preg_match('/\b(?:eval|assert)\s*\(\s*base64_decode\s*\(/i',$body))$signals[]='nested encoded execution';
     if(preg_match('/\b(?:file_put_contents|fwrite)\s*\(/i',$body)&&preg_match('/\b(?:base64_decode|gzinflate|gzuncompress)\s*\(/i',$body))$signals[]='write and decoder combination';
     if($signals&&count($hits)<30)$hits[]=['path'=>substr($path,strlen($root)+1),'signals'=>implode(', ',$signals)];
    }
   }
   $report[]=$r;
  }
  if(!$files)$errors[]='Zero PHP files inspected: review directory status, file access, and scanner limits.';
  update_option(self::LAST,['time'=>time(),'files'=>$files,'partial'=>$partial,'hits'=>$hits,'directories'=>$report,'errors'=>array_slice($errors,0,30)],false);
 }
 static function page(){if(!current_user_can('manage_options'))return;
  $events=get_option(self::EVENTS,[]);$last=get_option(self::LAST,[]);
  echo '<div class="wrap"><h1>Reinfection Investigation</h1><p>Read-only forensic leads. This page cannot identify the writer process without hosting-level audit logs. Events are observations at scan times, not continuous filesystem monitoring.</p>';
  echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'">';
  echo '<input type="hidden" name="action" value="wpsx_reinfection_scan">';wp_nonce_field('wpsx_reinfection_scan');
  submit_button('Run read-only investigation now','primary','submit',false);echo '</form>';
  if(isset($_GET['scan'])&&$_GET['scan']==='done')echo '<div class="notice notice-success"><p>Read-only investigation finished. See directory diagnostics below.</p></div>';
  echo '<h2>Last bounded source search</h2><p>PHP files inspected: '.intval($last['files']??0).' | Partial: '.(!empty($last['partial'])?'Yes':'No').' | Last: '.(!empty($last['time'])?esc_html(gmdate('Y-m-d H:i:s',(int)$last['time']).' UTC'):'Never').'</p>';
  echo '<h3>Directory diagnostics</h3><table class="widefat striped"><thead><tr><th>Directory</th><th>Status</th><th>PHP files</th><th>Folders visited</th><th>Skipped</th><th>Errors</th></tr></thead><tbody>';
  foreach(($last['directories']??[]) as $d)echo '<tr><td><code>'.esc_html($d['directory']).'</code></td><td>'.esc_html($d['status']).'</td><td>'.intval($d['files']).'</td><td>'.intval($d['directories']).'</td><td>'.intval($d['skipped']).'</td><td>'.intval($d['errors']).'</td></tr>';
  if(empty($last['directories']))echo '<tr><td colspan="6">No directory diagnostics recorded yet; run investigation now.</td></tr>';
  echo '</tbody></table>';
  if(!empty($last['errors'])){echo '<h3>Scanner warnings</h3><ul>';foreach($last['errors'] as $err)echo '<li>'.esc_html($err).'</li>';echo '</ul>';}
  echo '<table class="widefat striped"><thead><tr><th>Candidate file</th><th>Static indicators (not proof)</th></tr></thead><tbody>';
  foreach(($last['hits']??[]) as $h)echo '<tr><td><code>'.esc_html($h['path']).'</code></td><td>'.esc_html($h['signals']).'</td></tr>';
  if(empty($last['hits']))echo '<tr><td colspan="2">No leads in the bounded search; this does not establish a clean site.</td></tr>';
  echo '</tbody></table><h2>MU file changes and quarantine history</h2><table class="widefat striped"><thead><tr><th>UTC</th><th>Event</th><th>File</th><th>Detail</th></tr></thead><tbody>';
  foreach(array_slice(is_array($events)?$events:[],0,100) as $e)echo '<tr><td>'.esc_html(gmdate('Y-m-d H:i:s',(int)$e['time'])).'</td><td>'.esc_html($e['type']).'</td><td><code>'.esc_html($e['path']).'</code></td><td>'.esc_html($e['detail']).'</td></tr>';
  echo '</tbody></table><p>Next containment steps: inspect Hostinger scheduled tasks and access logs; rotate hosting, SFTP, WP admin and database credentials; review unknown administrators and plugin/theme integrity. Host-level audit/inotify is needed for reliable process attribution.</p></div>';
 }
}
WPSX_Reinfection_Investigation::init();
