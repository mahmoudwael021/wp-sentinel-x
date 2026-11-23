<?php
if (!defined('ABSPATH')) exit;
/** Read-only, bounded PHP inventory. No file deletion or repair. */
final class WPSX_Site_Monitor {
 const HOOK='wpsx_site_monitor_daily'; const BASE='wpsx_site_monitor_baseline'; const LAST='wpsx_site_monitor_last'; const ALERTS='wpsx_site_monitor_alerts';
 static function init(){add_action('init',[__CLASS__,'schedule']);add_action(self::HOOK,[__CLASS__,'run']);add_action('admin_menu',function(){add_submenu_page('wpsx','Site Monitoring','Site Monitoring','manage_options','wpsx_site_monitor',[__CLASS__,'page']);},45);add_action('admin_post_wpsx_site_monitor', [__CLASS__,'manual']);}
 static function schedule(){if(!wp_next_scheduled(self::HOOK))wp_schedule_event(time()+3600,'daily',self::HOOK);}
 static function scan(){
  $root=realpath(ABSPATH);$results=[];$count=0;$skipped=0;$limited=false;$start=microtime(true);
  if(!$root)return ['files'=>[],'count'=>0,'skipped'=>0,'limited'=>true,'error'=>'Document root unavailable'];
  $targets=[$root.'/wp-content/uploads',$root.'/wp-content/plugins',$root.'/wp-content/themes',$root.'/wp-content/mu-plugins'];
  foreach($targets as $target){if(!is_dir($target)||is_link($target))continue;
   try{$iter=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($target,FilesystemIterator::SKIP_DOTS|FilesystemIterator::CURRENT_AS_FILEINFO),RecursiveIteratorIterator::LEAVES_ONLY);
    foreach($iter as $entry){if($count>=4000 || microtime(true)-$start>18){$limited=true;break 2;}
     if($entry->isLink()||!$entry->isFile())continue;$path=$entry->getPathname();$rel=substr($path,strlen($root)+1);
     if(!preg_match('~\.(?:php[0-9]?|phtml|phar|inc)$~i',$path))continue;
     $count++;$size=$entry->getSize();if($size>2097152){$skipped++;continue;}
     $sha=@hash_file('sha256',$path);if(!$sha){$skipped++;continue;}
     $results[$rel]=['hash'=>$sha,'size'=>$size];
    }
   }catch(Throwable $e){$skipped++;}
  }
  ksort($results);return ['files'=>$results,'count'=>$count,'skipped'=>$skipped,'limited'=>$limited];
 }
 static function run(){
  $lock='wpsx_site_monitor_lock';$token=wp_generate_uuid4();if(!add_option($lock,['token'=>$token,'time'=>time()],'','no')){
   $old=get_option($lock);if(!is_array($old)||time()-(int)($old['time']??0)<300)return;
   delete_option($lock);if(!add_option($lock,['token'=>$token,'time'=>time()],'','no'))return;
  }
  try{$scan=self::scan();$prev=get_option(self::BASE,[]);$first=!is_array($prev)||empty($prev['created']);$alerts=[];
   if(!$first){foreach($scan['files'] as $path=>$data){if(!isset($prev['files'][$path]))$alerts[]=['type'=>'new','file'=>$path];elseif(($prev['files'][$path]['hash']??'')!==$data['hash'])$alerts[]=['type'=>'changed','file'=>$path];}
    // A partial inventory must never report missing files as deleted.
    if(!$scan['limited'] && !$scan['skipped'])foreach($prev['files'] as $path=>$data)if(!isset($scan['files'][$path]))$alerts[]=['type'=>'missing','file'=>$path];
   }
   $complete=!$scan['limited']&&!$scan['skipped']&&empty($scan['error']);
   // Never automatically accept a changed baseline; administrator must explicitly approve it.
   if($first && $complete)update_option(self::BASE,['created'=>time(),'files'=>$scan['files']],false);
   $last=['time'=>time(),'count'=>$scan['count'],'hashed'=>count($scan['files']),'skipped'=>$scan['skipped'],'limited'=>$scan['limited'],'complete'=>$complete,'first'=>$first,'alerts'=>count($alerts)];update_option(self::LAST,$last,false);
   update_option(self::ALERTS,array_slice($alerts,0,100),false);
   if($alerts){WPSX::log('site_monitor',count($alerts).' PHP file changes detected. Review Site Monitoring; no files modified.','critical');}
   elseif(!$complete)WPSX::log('site_monitor','Inventory incomplete (limit, unreadable or oversized files); baseline not changed.','warning');
   elseif($first)WPSX::log('site_monitor','Initial PHP inventory created; changes will be reported on later runs.');
  }catch(Throwable $e){WPSX::log('site_monitor','Monitor failed: '.substr($e->getMessage(),0,160),'critical');}
  finally{$current=get_option($lock);if(is_array($current)&&($current['token']??'')===$token)delete_option($lock);}
 }
 static function manual(){if(!current_user_can('manage_options'))wp_die('Unauthorized',403);check_admin_referer('wpsx_site_monitor');self::run();wp_safe_redirect(admin_url('admin.php?page=wpsx_site_monitor'));exit;}
 static function page(){if(!current_user_can('manage_options'))return;$last=get_option(self::LAST,[]);$base=get_option(self::BASE,[]);$alerts=get_option(self::ALERTS,[]);
  echo '<div class="wrap"><h1>WP Sentinel X — Site Monitoring v0.5.9</h1><p><strong>Read-only:</strong> inventories PHP-like files in uploads, plugins, themes and mu-plugins. Never quarantines, repairs, or deletes files. Scheduled daily; capped at 4,000 PHP files or 18 seconds per run. This is change detection, not a malware verdict.</p>';
  echo '<p><strong>Baseline:</strong> '.(!empty($base['created'])?esc_html(gmdate('Y-m-d H:i:s',(int)$base['created']).' UTC'):'Not established (first complete scan required)').'</p>';
  if(!empty($last['time']))echo '<p><strong>Last run:</strong> '.esc_html(gmdate('Y-m-d H:i:s',(int)$last['time']).' UTC').' | PHP candidates: '.intval($last['count']).' | Hashed: '.intval($last['hashed']).' | Skipped: '.intval($last['skipped']).' | Complete: '.(!empty($last['complete'])?'Yes':'No').' | Changes: '.intval($last['alerts']).'</p>';
  echo '<form action="'.esc_url(admin_url('admin-post.php')).'" method="post">';wp_nonce_field('wpsx_site_monitor');echo '<input type="hidden" name="action" value="wpsx_site_monitor">';submit_button('Run read-only monitoring now');echo '</form>';
  echo '<h2>Changes since baseline</h2><table class="widefat striped"><thead><tr><th>Type</th><th>File</th></tr></thead><tbody>';
  foreach((array)$alerts as $a)echo '<tr><td>'.esc_html($a['type']).'</td><td><code>'.esc_html($a['file']).'</code></td></tr>';
  if(!$alerts)echo '<tr><td colspan="2">No reported changes (not proof the site is clean).</td></tr>';
  echo '</tbody></table><p>Baseline is intentionally never auto-updated. A partial scan cannot establish a baseline or reliably detect deletions. Review changes against trusted sources before taking action.</p></div>';
 }
}
WPSX_Site_Monitor::init();
