<?php
if (!defined('ABSPATH')) exit;
/** Conservative opt-in recovery. No arbitrary PHP evaluation and no unverified replacements. */
final class WPSX_Auto_Recovery {
 const OPT='wpsx_auto_recovery_options'; const EVENTS='wpsx_auto_recovery_events'; const CRON='wpsx_auto_recovery_cron'; const LAST='wpsx_auto_recovery_last_run';
 static function settings(){return wp_parse_args(get_option(self::OPT,[]),['enabled'=>0,'quarantine'=>0,'index_repair'=>0,'core_webshell'=>0,'mu_loader'=>1,'staged_loader'=>1,'critical_core_repair'=>1]);}
 static function init(){
  add_filter('cron_schedules',function($s){$s['wpsx_fifteen_minutes']=['interval'=>900,'display'=>'Every 15 minutes'];return $s;});
  add_action('init',[__CLASS__,'schedule']);add_action(self::CRON,[__CLASS__,'run']);
  add_action('admin_menu',function(){add_submenu_page('wpsx','Auto Recovery','Auto Recovery','manage_options','wpsx_auto_recovery',[__CLASS__,'page']);},40);
  add_action('admin_post_wpsx_auto_recovery',[__CLASS__,'save']);
  add_action('admin_post_wpsx_auto_run',[__CLASS__,'manual']);
 }
 static function schedule(){if(!wp_next_scheduled(self::CRON))wp_schedule_event(time()+900,'wpsx_fifteen_minutes',self::CRON);}
 static function record($action,$file,$status,$detail){
  // Keep the last run summary in LAST, but avoid storing 96 identical healthy cron entries daily.
  if($action==='cron' && $status==='completed' && strpos($detail,'quarantined: 0; core repaired: 0; errors: 0')!==false){
   $day=gmdate('Y-m-d');
   if(get_option('wpsx_auto_recovery_heartbeat_day','')===$day)return;
   update_option('wpsx_auto_recovery_heartbeat_day',$day,false);
  }
  $events=get_option(self::EVENTS,[]);if(!is_array($events))$events=[];array_unshift($events,['time'=>time(),'action'=>$action,'file'=>$file,'status'=>$status,'detail'=>$detail]);update_option(self::EVENTS,array_slice($events,0,200),false);WPSX::log('auto_recovery',$action.' '.$file.': '.$status.' — '.$detail,$status==='failed'?'critical':'warning');}
 static function private_dir(){ $root=realpath(ABSPATH);if(!$root)return false;$dir=dirname($root).'/wpsx-private';if(is_link($dir))return false;if(!is_dir($dir)&&!@mkdir($dir,0700,true))return false;$real=realpath($dir);if(!$real||strpos($real,$root.DIRECTORY_SEPARATOR)===0||$real===$root)return false;return $real; }
 static function preserve($file,$hash){$dir=self::private_dir();if(!$dir)return false;$dest=$dir.'/auto-'.gmdate('Ymd-His').'-'.bin2hex(random_bytes(8)).'.evidence';if(!@copy($file,$dest))return false;@chmod($dest,0600);if(!hash_equals($hash,(string)@hash_file('sha256',$dest))){@unlink($dest);return false;}return $dest;}
 static function quarantine($file,$rel){$root=realpath(ABSPATH);$real=realpath($file);if(!$root||!$real||dirname($real)!==$root||is_link($file)||!is_file($file)||!is_readable($file)||!is_writable($file))return false;$size=@filesize($file);if($size===false||$size>8*1024*1024)return false;
  $body=@file_get_contents($file);if(!is_string($body))return false;
  $encoded=WPSX_Full_Scan::encoded_signals($body);$seo=WPSX_Full_Scan::seo_tamper($body);
  // Only correlated encoded-eval or SEO manipulation, never filename/severity alone.
  if(!$encoded&&!$seo)return false;
  $hash=@hash_file('sha256',$file);if(!$hash)return false;
  $evidence=self::preserve($file,$hash);if(!$evidence){self::record('quarantine',$rel,'failed','Could not preserve verified evidence');return false;}
  if(!hash_equals($hash,(string)@hash_file('sha256',$file))){self::record('quarantine',$rel,'failed','File changed before removal; evidence retained');return false;}
  if(!@unlink($file)){self::record('quarantine',$rel,'failed','Original could not be removed; evidence retained');return false;}
  self::record('quarantine',$rel,'success','Evidence: '.basename($evidence).' SHA256: '.$hash);return true;
 }
 /** Static-only detection: never evaluates or decompresses untrusted PHP. */
 static function mu_packed_loader_signature($body){
  if(!is_string($body)||strlen($body)<80)return false;
  // Static detection only: never decode or execute the submitted payload.
  // A huge nested eval(base64_decode(...)) MU loader does not need gzinflate
  // in its outer layer. Prior versions incorrectly required decompression.
  $nested=(bool)preg_match('/\beval\s*\(\s*base64_decode\s*\(/i',$body);
  $escaped=(preg_match_all('/\\\\(?:x[0-9a-fA-F]{2}|[0-7]{1,3})/', $body)>=100);
  $blob=(bool)preg_match('/[\x27\x22][A-Za-z0-9+\/=]{800,}[\x27\x22]/', $body);
  $decoder=(bool)preg_match('/\bbase64_decode\s*\(/i',$body);
  $inflate=(bool)preg_match('/\b(?:gzinflate|gzuncompress|gzdecode)\s*\(/i',$body);
  $execution=(bool)preg_match('/\b(?:eval|assert)\s*\(/i',$body);
  return ($nested && ($blob || $escaped || strlen($body)>32768))
      || ($decoder && $inflate && $execution && ($escaped || $blob));
 }
 static function quarantine_mu_loaders(&$stats){
  $root=realpath(ABSPATH);if(!$root)return;
  $base=$root.'/wp-content/mu-plugins';if(!is_dir($base)||is_link($base))return;
  $names=@scandir($base);if(!is_array($names)){$stats['errors']++;return;}
  foreach($names as $name){
   if($name==='.'||$name==='..'||!preg_match('/^[a-zA-Z0-9._-]+\.php$/iD',$name))continue;
   $file=$base.'/'.$name;$real=realpath($file);
   if(!$real||dirname($real)!==$base||is_link($file)||!is_file($file)||!is_readable($file))continue;
   $stats['mu_files_checked']=($stats['mu_files_checked']??0)+1;
   $size=@filesize($file);if($size===false||$size<200||$size>2*1024*1024)continue;
   $body=@file_get_contents($file);if(!is_string($body))continue;
   if(!self::mu_packed_loader_signature($body))continue;
   $rel='wp-content/mu-plugins/'.$name;
   if(!is_writable($file)){$stats['errors']++;self::record('mu_loader',$rel,'failed','Packed loader detected but file is not writable');continue;}
   $hash=@hash_file('sha256',$file);if(!$hash){$stats['errors']++;continue;}
   $evidence=self::preserve($file,$hash);
   if(!$evidence){$stats['errors']++;self::record('mu_loader',$rel,'failed','Could not preserve verified evidence');continue;}
   if(!hash_equals($hash,(string)@hash_file('sha256',$file))){$stats['errors']++;self::record('mu_loader',$rel,'failed','File changed before quarantine; evidence retained');continue;}
   if(!@unlink($file)){$stats['errors']++;self::record('mu_loader',$rel,'failed','Quarantine failed; evidence retained');continue;}
   $stats['quarantined']++;if(class_exists('WPSX_Reinfection_Investigation'))WPSX_Reinfection_Investigation::quarantined($rel,$hash);self::record('mu_loader',$rel,'success','Packed must-use plugin loader; evidence '.basename($evidence).' SHA256 '.$hash);
  }
  self::record('mu_loader','wp-content/mu-plugins','checked','Inspected '.(int)($stats['mu_files_checked']??0).' MU PHP files; quarantined total '.(int)$stats['quarantined']);
 }
 /** Bounded scan for highly distinctive fragmented loaders outside standard plugins/themes. */
 static function quarantine_staged_loaders(&$stats){
  $root=realpath(ABSPATH);if(!$root)return;
  $base=$root.'/wp-content';if(!is_dir($base)||is_link($base))return;
  $queue=[$base];$dirs=0;$files=0;$deadline=microtime(true)+6;
  while($queue && $dirs<250 && $files<2500 && microtime(true)<$deadline){
   $dir=array_shift($queue);$dirs++;$names=@scandir($dir);if(!is_array($names)){$stats['errors']++;continue;}
   foreach($names as $name){
    if($files>=2500 || microtime(true)>=$deadline)break;
    if($name==='.'||$name==='..')continue;
    $path=$dir.'/'.$name;if(is_link($path))continue;
    if(is_dir($path)){
     if($dir===$base && in_array($name,['plugins','themes','wflogs','cache'],true))continue;
     if(count($queue)<1000)$queue[]=$path;
     continue;
    }
    if(!is_file($path)||!preg_match('/\.(?:php[0-9]?|phtml|phar)$/i',$name))continue;
    $files++;$stats['staged_files_checked']=($stats['staged_files_checked']??0)+1;
    $real=realpath($path);if(!$real||strpos($real,$base.DIRECTORY_SEPARATOR)!==0)continue;
    $size=@filesize($path);if($size===false||$size<8192||$size>4*1024*1024)continue;
    $body=@file_get_contents($path);if(!is_string($body)||!WPSX_Full_Scan::fragmented_loader_signals($body))continue;
    $rel=substr($real,strlen($root)+1);$hash=@hash_file('sha256',$path);
    if(!$hash||!is_writable($path)){$stats['errors']++;self::record('staged_loader',$rel,'failed','Detected but inaccessible for quarantine');continue;}
    $evidence=self::preserve($path,$hash);
    if(!$evidence){$stats['errors']++;self::record('staged_loader',$rel,'failed','Evidence preservation failed');continue;}
    if(!hash_equals($hash,(string)@hash_file('sha256',$path))){$stats['errors']++;self::record('staged_loader',$rel,'failed','File changed during inspection');continue;}
    if(!@unlink($path)){$stats['errors']++;self::record('staged_loader',$rel,'failed','Removal failed; evidence retained');continue;}
    $stats['quarantined']++;self::record('staged_loader',$rel,'success','Fragmented staged loader; evidence '.basename($evidence).' SHA256 '.$hash);
   }
  }
  if($queue)self::record('staged_loader','—','partial','Bounded scan incomplete; remaining directories require full site scan');
 }
 /** Restore only checksum-verified WordPress bootstrap files; never delete a core file. */
 static function repair_critical_core(&$stats){
  $files=['wp-blog-header.php','wp-load.php','wp-settings.php','wp-includes/version.php'];
  $checks=WPSX::core_files();
  if(is_wp_error($checks)||!is_array($checks)||count($checks)<500){
   $stats['errors']++;self::record('critical_core_repair','—','failed','Official WordPress checksum manifest unavailable; no replacements attempted');return;
  }
  foreach($files as $relative){
   if(!isset($checks[$relative])){$stats['errors']++;self::record('critical_core_repair',$relative,'failed','File absent from official checksum manifest');continue;}
   $path=ABSPATH.$relative;
   if(is_link($path)){$stats['errors']++;self::record('critical_core_repair',$relative,'failed','Symlink rejected');continue;}
   $actual=is_file($path)?@md5_file($path):false;
   if(is_string($actual)&&hash_equals(strtolower($checks[$relative]),strtolower($actual)))continue;
   $stats['core_mismatches']=($stats['core_mismatches']??0)+1;
   $result=WPSX::repair($relative);
   if(is_wp_error($result)){
    $stats['errors']++;self::record('critical_core_repair',$relative,'failed',$result->get_error_message());continue;
   }
   $stats['core_repaired']=($stats['core_repaired']??0)+1;
   self::record('critical_core_repair',$relative,'success','Official WordPress checksum verified before and after restoration; original preserved outside webroot');
  }
 }
 /** Opt-in: quarantine non-distribution PHP web shells inside wp-includes only. */
 static function quarantine_core_webshells(&$stats){
  $root=realpath(ABSPATH);if(!$root)return;
  $base=$root.'/wp-includes';if(!is_dir($base)||is_link($base))return;
  $checks=WPSX_Full_Scan::official_core();
  // Fail closed if the authoritative manifest cannot be obtained.
  if(!is_array($checks)||count($checks)<500){self::record('core_webshell','—','skipped','Official WordPress core checksum manifest unavailable');return;}
  $todo=[[$base,0]];$visited=0;$deadline=microtime(true)+8;
  while($todo && $visited<3000 && microtime(true)<$deadline){
   [$dir,$depth]=array_pop($todo);$items=@scandir($dir);if(!is_array($items))continue;
   foreach($items as $name){
    if($name==='.'||$name==='..')continue;
    $p=$dir.'/'.$name;if(is_link($p))continue;
    if(is_dir($p)){if($depth<5)$todo[]=[$p,$depth+1];continue;}
    if(!is_file($p)||!preg_match('/\.(?:php|phtml|phar)$/i',$name))continue;
    $visited++;$stats['core_files_checked']=($stats['core_files_checked']??0)+1;
    $real=realpath($p);if(!$real||strpos($real,$base.DIRECTORY_SEPARATOR)!==0)continue;
    $rel=substr($real,strlen($root)+1);
    if(array_key_exists($rel,$checks))continue; // Never auto-remove official core files.
    $size=@filesize($p);if(!$size||$size>2*1024*1024)continue;
    $body=@file_get_contents($p);if(!is_string($body))continue;
    // Require both a file-manager/webshell capability and an execution or unauthenticated access primitive.
    $filemgr=(bool)preg_match('/\b(?:move_uploaded_file|is_uploaded_file|scandir|opendir|readdir)\s*\(/i',$body);
    $mutation=(bool)preg_match('/\b(?:file_put_contents|fwrite|unlink|rename|chmod|mkdir)\s*\(/i',$body);
    $execution=(bool)preg_match('/\b(?:eval|shell_exec|system|passthru|proc_open|popen)\s*\(/i',$body);
    $unprotected=(bool)preg_match('/[\"\']authorize[\"\']\s*[:=]>?\s*[\"\']?0\b/i',$body);
    if(!$filemgr||!$mutation||!($execution||$unprotected))continue;
    $stats['core_webshell_matches']=($stats['core_webshell_matches']??0)+1;
    // Limit to confirmed webshell-like unknown core files; preserve evidence before removal.
    $hash=@hash_file('sha256',$p);if(!$hash||!is_writable($p))continue;
    $evidence=self::preserve($p,$hash);
    if(!$evidence){$stats['errors']++;self::record('core_webshell',$rel,'failed','Evidence preservation failed');continue;}
    if(!hash_equals($hash,(string)@hash_file('sha256',$p))){$stats['errors']++;self::record('core_webshell',$rel,'failed','File changed; original retained');continue;}
    if(!@unlink($p)){$stats['errors']++;self::record('core_webshell',$rel,'failed','Removal failed; evidence retained');continue;}
    $stats['quarantined']++;self::record('core_webshell',$rel,'success','Non-core webshell indicators; evidence '.basename($evidence).' SHA256 '.$hash);
   }
  }
  if($todo)self::record('core_webshell','—','partial','Bounded scan; additional directories pending next run');
 }
 static function repair_index(){
  $root=realpath(ABSPATH);if(!$root)return;
  $file=$root.'/index.php';if(!is_file($file)||is_link($file)||!is_readable($file)||!is_writable($file))return;
  $checks=WPSX_Full_Scan::official_core();$expected=$checks['index.php']??null;
  if(is_array($expected))$expected=$expected[0]??null;
  if(!is_string($expected)||!preg_match('/^[a-f0-9]{32}$/i',$expected))return;
  $current=@md5_file($file);if($current&&hash_equals(strtolower($expected),strtolower($current)))return;
  // Standard WP front-controller candidate, only accepted if matching official checksum.
  $candidate="<?php\n/**\n * Front to the WordPress application. This file doesn't do anything, but loads\n * wp-blog-header.php which does and tells WordPress to load the theme.\n *\n * @package WordPress\n */\n\n/**\n * Tells WordPress to load the WordPress theme and output it.\n *\n * @var bool\n */\ndefine( 'WP_USE_THEMES', true );\n\n/** Loads the WordPress Environment and Template */\nrequire __DIR__ . '/wp-blog-header.php';\n";
  if(!hash_equals(strtolower($expected),md5($candidate))){self::record('index_repair','index.php','skipped','Official checksum does not match built-in candidate; no replacement');return;}
  $sha=@hash_file('sha256',$file);$evidence=$sha?self::preserve($file,$sha):false;
  if(!$evidence){self::record('index_repair','index.php','failed','Could not preserve evidence; no replacement');return;}
  if(!hash_equals($sha,(string)@hash_file('sha256',$file))){self::record('index_repair','index.php','failed','File changed during repair; no replacement');return;}
  $tmp=@tempnam($root,'.wpsx-');if(!$tmp){self::record('index_repair','index.php','failed','Could not create temporary file');return;}
  @chmod($tmp,0600);
  if(@file_put_contents($tmp,$candidate,LOCK_EX)===false||!hash_equals(strtolower($expected),(string)@md5_file($tmp))){@unlink($tmp);self::record('index_repair','index.php','failed','Temporary replacement failed checksum');return;}
  if(!hash_equals($sha,(string)@hash_file('sha256',$file))){@unlink($tmp);self::record('index_repair','index.php','failed','Original changed; no replacement');return;}
  if(!@rename($tmp,$file)){@unlink($tmp);self::record('index_repair','index.php','failed','Atomic replacement failed');return;}
  @chmod($file,0644);
  if(!hash_equals(strtolower($expected),(string)@md5_file($file))){self::record('index_repair','index.php','failed','Post-repair checksum mismatch; manual intervention required');return;}
  self::record('index_repair','index.php','success','Official checksum verified; original saved as '.basename($evidence));
 }
 static function run(){
  // add_option is atomic at the database unique-key level, unlike a transient get/set pair.
  $lock='wpsx_auto_recovery_lock';$token=wp_generate_uuid4();$now=time();
  if(!add_option($lock,['token'=>$token,'time'=>$now],'','no')){
   $old=get_option($lock);
   if(!is_array($old)||empty($old['time'])||$now-(int)$old['time']<600)return;
   // Stale lock: a prior process died. No unsafe takeover if another process changed it.
   if(get_option($lock)!==$old)return;
   delete_option($lock);
   if(!add_option($lock,['token'=>$token,'time'=>$now],'','no'))return;
  }
  $stats=['started'=>$now,'finished'=>null,'status'=>'running','scanned'=>0,'candidates'=>0,'quarantined'=>0,'core_mismatches'=>0,'core_repaired'=>0,'errors'=>0];
  try{
   $settings=self::settings();
   if(empty($settings['enabled'])){$stats['status']='disabled';return;}
   if(!empty($settings['critical_core_repair']))self::repair_critical_core($stats);
   if(!empty($settings['index_repair']))self::repair_index();
   if(!empty($settings['core_webshell']))self::quarantine_core_webshells($stats);
   if(!empty($settings['mu_loader']))self::quarantine_mu_loaders($stats);
   if(class_exists('WPSX_Reinfection_Investigation'))WPSX_Reinfection_Investigation::inspect();
   if(!empty($settings['staged_loader']))self::quarantine_staged_loaders($stats);
   if(!empty($settings['quarantine'])){
    $root=realpath(ABSPATH);
    if(!$root){$stats['errors']++;}
    else{
     $names=@scandir($root);
     if(!is_array($names)){$stats['errors']++;}
     else foreach($names as $name){
      if($name==='.'||$name==='..'||!preg_match('/^[a-zA-Z0-9._-]+$/D',$name)||strpos($name,'..')!==false)continue;
      if(!preg_match('/\.(?:php[0-9]?|phtml|txt|dat|inc)$/i',$name))continue;
      if(in_array(strtolower($name),['index.php','wp-config.php','wp-load.php','wp-settings.php','wp-blog-header.php','wordfence-waf.php'],true))continue;
      $stats['candidates']++;$file=$root.'/'.$name;
      if(is_file($file)&&!is_link($file)){$stats['scanned']++;if(self::quarantine($file,$name))$stats['quarantined']++;}
     }
    }
   }
   $stats['status']=$stats['errors']?'partial':'completed';
  }catch(Throwable $e){$stats['status']='failed';$stats['errors']++;self::record('cron','—','failed','Unhandled recovery error: '.substr($e->getMessage(),0,250));}
  finally{
   $stats['finished']=time();update_option(self::LAST,$stats,false);
   self::record('cron','—',$stats['status'],'Scanned: '.$stats['scanned'].'; candidates: '.$stats['candidates'].'; quarantined: '.$stats['quarantined'].'; core repaired: '.$stats['core_repaired'].'; errors: '.$stats['errors']);
   $current=get_option($lock);if(is_array($current)&&($current['token']??'')===$token)delete_option($lock);
  }
 }
 static function save(){if(!current_user_can('manage_options'))wp_die('Unauthorized',403);check_admin_referer('wpsx_auto_recovery');update_option(self::OPT,['enabled'=>!empty($_POST['enabled'])?1:0,'quarantine'=>!empty($_POST['quarantine'])?1:0,'index_repair'=>!empty($_POST['index_repair'])?1:0,'core_webshell'=>!empty($_POST['core_webshell'])?1:0,'mu_loader'=>!empty($_POST['mu_loader'])?1:0,'staged_loader'=>!empty($_POST['staged_loader'])?1:0,'critical_core_repair'=>!empty($_POST['critical_core_repair'])?1:0],false);WPSX::log('auto_recovery','Auto recovery settings changed','warning');wp_safe_redirect(admin_url('admin.php?page=wpsx_auto_recovery'));exit;}
 static function manual(){if(!current_user_can('manage_options'))wp_die('Unauthorized',403);check_admin_referer('wpsx_auto_run');self::run();wp_safe_redirect(admin_url('admin.php?page=wpsx_auto_recovery'));exit;}
 static function page(){if(!current_user_can('manage_options'))return;$s=self::settings();$events=get_option(self::EVENTS,[]);echo '<div class="wrap"><h1>WP Sentinel X — Auto Recovery v0.6.12</h1><p><strong>Development build:</strong> disabled by default. First test on staging with an independent backup. Automatic actions include opt-in detection of non-distribution web shells inside wp-includes; this is experimental and can produce false positives. No automatic deletion of plugin/theme files or Google verification HTML.</p>';
  echo '<p>WP-Cron attempts a run every 15 minutes when traffic triggers it. This is not continuous monitoring. A server-side cron is needed for reliable scheduling.</p>'; $last=get_option(self::LAST,[]); if(is_array($last)&&!empty($last['finished']))echo '<p><strong>Last execution:</strong> '.esc_html(gmdate('Y-m-d H:i:s', (int)$last['finished'])).' UTC | '.esc_html($last['status']).' | Files read: '.intval($last['scanned']).' | Quarantined: '.intval($last['quarantined']).' | Core repaired: '.intval($last['core_repaired']??0).' | Errors: '.intval($last['errors']).'</p>'; echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'">';wp_nonce_field('wpsx_auto_recovery');echo '<input type="hidden" name="action" value="wpsx_auto_recovery">';foreach(['enabled'=>'Enable automatic recovery (opt-in)','quarantine'=>'Auto quarantine confirmed malicious standalone root scripts','index_repair'=>'Auto repair root index.php only when official WordPress checksum matches replacement','critical_core_repair'=>'Auto restore modified critical WordPress core bootstrap files (including wp-blog-header.php) from checksum-verified originals; preserve evidence','core_webshell'=>'EXPERIMENTAL: Auto quarantine unknown wp-includes PHP web shells (official manifest + multiple behavior indicators; evidence retained)','mu_loader'=>'Auto quarantine high-confidence packed PHP loaders in mu-plugins (evidence retained)','staged_loader'=>'Auto quarantine high-confidence fragmented staged loaders in wp-content (excludes standard plugins/themes; evidence retained)'] as $key=>$label)echo '<p><label><input type="checkbox" name="'.esc_attr($key).'" value="1" '.checked(!empty($s[$key]),true,false).'> '.esc_html($label).'</label></p>';submit_button('Save auto recovery settings');echo '</form><form method="post" action="'.esc_url(admin_url('admin-post.php')).'">';wp_nonce_field('wpsx_auto_run');echo '<input type="hidden" name="action" value="wpsx_auto_run">';submit_button('Run configured recovery now (test)','secondary');echo '</form><h2>Auto Recovery Activity Log</h2>';
  $events=is_array($events)?$events:[];
  $filter=isset($_GET['wpsx_log_filter'])?sanitize_key(wp_unslash($_GET['wpsx_log_filter'])):'all';
  $allowed=['all','threats','quarantine','index_repair','critical_core_repair','errors','cron'];
  if(!in_array($filter,$allowed,true))$filter='all';
  $filtered=array_values(array_filter($events,static function($e)use($filter){
   if(!is_array($e))return false;
   $action=(string)($e['action']??'');$status=(string)($e['status']??'');
   if($filter==='all')return true;
   if($filter==='errors')return in_array($status,['failed','partial','error'],true);
   if($filter==='threats')return in_array($action,['quarantine','index_repair','critical_core_repair','core_webshell','mu_loader','staged_loader'],true);
   return $action===$filter;
  }));
  $per_page=25;$total=count($filtered);$pages=max(1,(int)ceil($total/$per_page));
  $page=isset($_GET['wpsx_log_page'])?max(1,absint($_GET['wpsx_log_page'])):1;$page=min($page,$pages);
  $base=admin_url('admin.php?page=wpsx_auto_recovery');
  echo '<form method="get" style="margin:12px 0"><input type="hidden" name="page" value="wpsx_auto_recovery"><label for="wpsx-log-filter">Filter: </label><select id="wpsx-log-filter" name="wpsx_log_filter">';
  foreach(['all'=>'All','threats'=>'Threat actions','quarantine'=>'Quarantines','index_repair'=>'Index repairs','critical_core_repair'=>'Critical core repairs','errors'=>'Errors','cron'=>'Cron summaries'] as $value=>$label){echo '<option value="'.esc_attr($value).'" '.selected($filter,$value,false).'>'.esc_html($label).'</option>';}
  echo '</select> <button class="button" type="submit">Apply</button> <span style="margin-left:12px">'.intval($total).' records (up to 200 recent events retained)</span></form>';
  echo '<table class="widefat striped"><thead><tr><th>UTC time</th><th>Action</th><th>File</th><th>Status</th><th>Detail</th></tr></thead><tbody>';
  foreach(array_slice($filtered,($page-1)*$per_page,$per_page) as $e){echo '<tr><td>'.esc_html(gmdate('Y-m-d H:i:s',(int)($e['time']??0))).'</td><td>'.esc_html($e['action']??'').'</td><td>'.esc_html($e['file']??'').'</td><td>'.esc_html($e['status']??'').'</td><td style="overflow-wrap:anywhere">'.esc_html($e['detail']??'').'</td></tr>';}
  if(!$total)echo '<tr><td colspan="5">No matching records.</td></tr>';
  echo '</tbody></table>';
  if($pages>1){echo '<div class="tablenav"><div class="tablenav-pages" style="margin:12px 0">';
   echo wp_kses_post(paginate_links(['base'=>add_query_arg(['wpsx_log_filter'=>$filter,'wpsx_log_page'=>'%#%'],$base),'format'=>'','current'=>$page,'total'=>$pages,'prev_text'=>'&laquo; Previous','next_text'=>'Next &raquo;','type'=>'plain']));
   echo '</div></div>';
  }
  echo '<p>Last execution summary is updated on every run. Healthy no-action cron runs are logged once per UTC day to reduce noise. Threat, repair and error records remain individually logged. Evidence is saved in the private directory outside the web root. These automatic records are separate from the manual Quarantine Manager. Restore requires manual review.</p></div>';}

}
WPSX_Auto_Recovery::init();
