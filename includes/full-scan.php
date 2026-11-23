<?php
if (!defined('ABSPATH')) exit;
/** Incremental scanner with explicitly confirmed quarantine for verified encoded payloads. */
final class WPSX_Full_Scan {
 const STATE='wpsx_full_scan_state'; const FINDINGS='wpsx_full_scan_findings'; const QUARANTINE='wpsx_full_quarantine_records';
 static function init(){add_action('admin_menu',[__CLASS__,'menu'],30);add_action('wp_ajax_wpsx_full_start',[__CLASS__,'start']);add_action('wp_ajax_wpsx_full_step',[__CLASS__,'step']);add_action('wp_ajax_wpsx_full_results',[__CLASS__,'results']);add_action('admin_post_wpsx_full_quarantine',[__CLASS__,'quarantine']);add_action('admin_post_wpsx_full_restore',[__CLASS__,'restore']);}
 static function allowed(){if(!current_user_can('manage_options'))wp_send_json_error('Unauthorized',403);check_ajax_referer('wpsx_full_scan','nonce');}
 static function root(){return realpath(ABSPATH);}
 static function relative($p){$root=self::root();return $root && strpos($p,$root.DIRECTORY_SEPARATOR)===0?substr($p,strlen($root)+1):'';}
 static function start(){self::allowed();$root=self::root();if(!$root)wp_send_json_error('Document root unavailable');$state=['queue'=>[$root],'files'=>[],'visited'=>0,'dirs'=>0,'skipped'=>0,'findings'=>0,'started'=>time(),'finished'=>false,'limit'=>200000,'error'=>'','verified'=>0,'scanned_bytes'=>0];update_option(self::STATE,$state,false);update_option(self::FINDINGS,[],false);wp_send_json_success(self::summary($state));}
 static function summary($s){return ['visited'=>$s['visited'],'dirs'=>$s['dirs'],'skipped'=>$s['skipped'],'findings'=>$s['findings'],'finished'=>$s['finished'],'error'=>$s['error']??'','queued'=>count($s['queue'])+count($s['files']),'verified'=>$s['verified']??0];}
 static function step(){self::allowed();$s=get_option(self::STATE);if(!is_array($s))wp_send_json_error('Start a scan first');if(!empty($s['finished']))wp_send_json_success(self::summary($s));$root=self::root();$deadline=microtime(true)+5;$processed=0;$findings=get_option(self::FINDINGS,[]);if(!is_array($findings))$findings=[];
 while(microtime(true)<$deadline && $processed<120 && ($s['queue'] || $s['files'])){
  if($s['files']){$p=array_pop($s['files']);$processed++;$s['visited']++;self::inspect($p,$root,$findings,$s);if($s['visited']>=$s['limit']){$s['error']='File safety limit reached; scan is incomplete';$s['finished']=true;break;}continue;}
  $dir=array_shift($s['queue']);$s['dirs']++;if(is_link($dir)||!is_dir($dir)){$s['skipped']++;continue;}$real=realpath($dir);if(!$real || ($real!==$root && strpos($real,$root.DIRECTORY_SEPARATOR)!==0)){$s['skipped']++;continue;}
  $names=@scandir($dir);if(!is_array($names)){$s['skipped']++;continue;}foreach($names as $name){if($name==='.'||$name==='..')continue;$p=$dir.DIRECTORY_SEPARATOR.$name;if(is_link($p)){$s['skipped']++;continue;}if(is_dir($p))$s['queue'][]=$p;elseif(is_file($p))$s['files'][]=$p;else $s['skipped']++;}
  if(count($s['queue'])+count($s['files'])>200000){$s['error']='Queue safety limit reached; scan is incomplete';$s['finished']=true;break;}
 }
 if(!$s['queue']&&!$s['files'])$s['finished']=true;$s['findings']=count($findings);update_option(self::STATE,$s,false);update_option(self::FINDINGS,$findings,false);if($s['finished']){update_option('wpsx_full_last_scan',time(),false);WPSX::log('full_scan','Read-only full scan completed: '.$s['visited'].' files; '.$s['findings'].' findings'.($s['error']?' (incomplete)':''),$s['findings']?'warning':'info');}wp_send_json_success(self::summary($s));
 }
 static function results(){self::allowed();$items=get_option(self::FINDINGS,[]);wp_send_json_success(['items'=>array_slice(is_array($items)?$items:[],0,200)]);}
 static function add(&$findings,$path,$type,$detail,$severity){if(count($findings)>=1000)return;$findings[]=['path'=>$path,'type'=>$type,'detail'=>$detail,'severity'=>$severity];}
 static function quarantine(){
  if(!current_user_can('manage_options'))wp_die('Unauthorized',403);
  check_admin_referer('wpsx_full_quarantine');
  $rel=isset($_POST['path'])?wp_unslash($_POST['path']):'';
  $expected=isset($_POST['sha256'])?wp_unslash($_POST['sha256']):'';
  $message='Quarantine blocked.';
  $root=self::root();
  if(is_string($rel)&&preg_match('~^[a-zA-Z0-9._/-]+$~D',$rel)&&strpos($rel,'..')===false&&strpos($rel,'/')===false&&preg_match('/^[a-f0-9]{64}$/D',$expected)&&$root){
   $p=$root.DIRECTORY_SEPARATOR.$rel;
   $real=realpath($p);
   $findings=get_option(self::FINDINGS,[]);$eligible=false;
   foreach((array)$findings as $f){if(($f['path']??'')===$rel&&in_array(($f['type']??''),['encoded_payload','seo_tamper'],true)&&($f['severity']??'')==='high'){$eligible=true;break;}}
   if($eligible&&$real===$p&&!is_link($p)&&is_file($p)&&is_readable($p)&&is_writable($p)&&filesize($p)<=8*1024*1024&&hash_equals($expected,(string)hash_file('sha256',$p))){
    $body=@file_get_contents($p);
    $signals=is_string($body)?self::encoded_signals($body):[];
    if($signals || self::seo_tamper((string)$body)){
     $private=self::evidence_dir();
     if(strpos($private,$root.DIRECTORY_SEPARATOR)!==0 && !is_link($private) && (is_dir($private)||@mkdir($private,0700,true))){
      $dest=$private.DIRECTORY_SEPARATOR.'quarantine-'.gmdate('Ymd-His').'-'.bin2hex(random_bytes(8)).'.evidence';
      if(@copy($p,$dest)&&hash_equals($expected,(string)@hash_file('sha256',$dest))){
       @chmod($dest,0600);
       if(@unlink($p)){
        $message='Quarantined '.$rel.'; evidence preserved outside document root.';
        $records=get_option(self::QUARANTINE,[]);if(!is_array($records))$records=[];
        $records[]=['id'=>basename($dest),'original'=>$rel,'sha256'=>$expected,'time'=>time(),'status'=>'quarantined'];
        update_option(self::QUARANTINE,array_slice($records,-500),false);
        $items=array_values(array_filter((array)$findings,function($f)use($rel){return ($f['path']??'')!==$rel;}));
        update_option(self::FINDINGS,$items,false);
        WPSX::log('quarantine',$message,'warning');
       }else{$message='Evidence saved, but original file could not be removed.';}
      }else{$message='Could not safely preserve evidence; original unchanged.';if(is_file($dest))@unlink($dest);}
     }else{$message='Private quarantine directory unavailable outside webroot.';}
    }else{$message='Malware signature no longer confirmed; run a new scan.';}
   }else{$message='File changed, inaccessible, or no longer an eligible high-confidence finding; run a new scan.';}
  }
  set_transient('wpsx_full_notice_'.get_current_user_id(),$message,120);
  wp_safe_redirect(admin_url('admin.php?page=wpsx_full_scan'));exit;
 }
 static function evidence_dir(){ $root=self::root();return $root?dirname($root).DIRECTORY_SEPARATOR.'wpsx-private':''; }
 static function restore(){
  if(!current_user_can('manage_options'))wp_die('Unauthorized',403);
  check_admin_referer('wpsx_full_restore');
  $id=isset($_POST['evidence_id'])?sanitize_file_name(wp_unslash($_POST['evidence_id'])):'';
  $message='Restore blocked.';$records=get_option(self::QUARANTINE,[]);$root=self::root();$dir=self::evidence_dir();
  if($root&&is_array($records)&&preg_match('/^quarantine-[0-9]{8}-[0-9]{6}-[a-f0-9]{16}\.evidence$/D',$id)){
   foreach($records as $i=>$rec){if(($rec['id']??'')!==$id||($rec['status']??'')!=='quarantined')continue;
    $rel=$rec['original']??'';$hash=$rec['sha256']??'';
    if(!is_string($rel)||!preg_match('/^[a-zA-Z0-9._-]+$/D',$rel)||strpos($rel,'..')!==false||!preg_match('/^[a-f0-9]{64}$/D',$hash))break;
    $source=$dir.DIRECTORY_SEPARATOR.$id;$target=$root.DIRECTORY_SEPARATOR.$rel;
    if(is_link($dir)||!is_dir($dir)||is_link($source)||!is_file($source)||!is_readable($source)||file_exists($target)||is_link($target)){$message='Evidence missing or original path already exists; nothing overwritten.';break;}
    if(!hash_equals($hash,(string)@hash_file('sha256',$source))){$message='Evidence hash mismatch; restore refused.';break;}
    // Exclusive creation: do not overwrite an existing target or follow a symlink.
    $in=@fopen($source,'rb');$out=@fopen($target,'x+b');
    if(!$in||!$out){if($in)fclose($in);if($out)fclose($out);$message='Could not create restored file.';break;}
    $copied=@stream_copy_to_stream($in,$out);fclose($in);fclose($out);
    if($copied===false||!hash_equals($hash,(string)@hash_file('sha256',$target))){@unlink($target);$message='Restore integrity verification failed.';break;}
    @chmod($target,0600);$records[$i]['status']='restored';$records[$i]['restored_at']=time();update_option(self::QUARANTINE,$records,false);
    $message='Restored '.$rel.' (evidence copy retained). WARNING: this file was classified as malicious; do not execute it.';
    WPSX::log('quarantine_restore',$message,'warning');break;
   }
  }
  set_transient('wpsx_full_notice_'.get_current_user_id(),$message,120);
  wp_safe_redirect(admin_url('admin.php?page=wpsx_full_scan'));exit;
 }
 static function seo_tamper($body){
  // Correlated signals: root PHP script writing robots.txt and a Google verification file.
  return preg_match('/(?:file_put_contents|fopen)\s*\(/i',$body)
   && preg_match('/robots\.txt/i',$body)
   && preg_match('/google-site-verification|google[a-z0-9]{12,}\.html/i',$body);
 }
 static function benign_index($p,$norm,$size){if(strtolower(basename($norm))!=='index.php'||$size>4096)return false;$body=@file_get_contents($p);if(!is_string($body))return false;$body=preg_replace('~/\*.*?\*/~s','',$body);$body=preg_replace('~//[^\r\n]*|\#[^\r\n]*~','',$body);$body=preg_replace('/<\?(?:php)?|\?>/i','',$body);return trim($body)==='';}
 static function official_core(){
  static $checks=null;if($checks!==null)return $checks;
  require_once ABSPATH.'wp-admin/includes/update.php';global $wp_version;
  $locale=get_locale();$checks=get_core_checksums($wp_version,$locale);
  if(!is_array($checks))$checks=get_core_checksums($wp_version,'en_US');
  if(!is_array($checks))$checks=[];return $checks;
 }
 static function official_plugin($slug){
  static $cache=[];if(array_key_exists($slug,$cache))return $cache[$slug];
  $main=WP_PLUGIN_DIR.'/'.$slug; if(!is_dir($main))return $cache[$slug]=[];
  $version='';foreach(glob($main.'/*.php')?:[] as $file){$header=@file_get_contents($file,false,null,0,8192);if(preg_match('/^[ \t*#\/]*Version:\s*([^\r\n]+)/mi',(string)$header,$m)){ $version=trim($m[1]);break;}}
  if(!$version)return $cache[$slug]=[];
  $key='wpsx_ck_'.md5($slug.'|'.$version);$stored=get_transient($key);
  if(is_array($stored))return $cache[$slug]=$stored;
  $url='https://downloads.wordpress.org/plugin-checksums/'.rawurlencode($slug).'/'.rawurlencode($version).'.json';
  $res=wp_safe_remote_get($url,['timeout'=>3,'limit_response_size'=>3*1024*1024]);$checks=[];
  if(!is_wp_error($res)&&wp_remote_retrieve_response_code($res)===200){$json=json_decode(wp_remote_retrieve_body($res),true);if(isset($json['checksums'])&&is_array($json['checksums']))$checks=$json['checksums'];}
  set_transient($key,$checks,$checks?DAY_IN_SECONDS:2*HOUR_IN_SECONDS);
  return $cache[$slug]=$checks;
 }
 /** Root inventory: unknown executable files are reviewed even without malware signatures. */
 static function root_anomaly($norm,$size,$is_php,$is_benign_index=false){
  if(strpos($norm,'/')!==false)return null;
  $name=strtolower($norm);
  if($is_php){
   if($is_benign_index && $name==='index.php')return null;
   $known=['index.php','wp-activate.php','wp-blog-header.php','wp-comments-post.php','wp-config.php','wp-config-sample.php','wp-cron.php','wp-links-opml.php','wp-load.php','wp-login.php','wp-mail.php','wp-settings.php','wp-signup.php','wp-trackback.php','xmlrpc.php'];
   if(in_array($name,$known,true))return null;
   if(preg_match('/(?:infector|webshell|shell|backdoor|cmd|mailer|inject)/i',$name))return ['high','Unexpected root PHP with suspicious filename; inspect content and origin'];
   return ['medium','Unexpected executable PHP file in WordPress root; verify provenance (not confirmed malware)'];
  }
  if(preg_match('/\.(?:php[0-9]?|phtml|phar|inc)(?:\.old|\.bak|\.save|~)?$/i',$name))return ['medium','Executable or backup PHP-like file in WordPress root; inspect server handler and origin'];
  if(!preg_match('/\./',$name) && $size>0 && !in_array($name,['license','readme'],true))return ['low','Unrecognized extensionless file in WordPress root; review origin'];
  return null;
 }
 /** Bounded, non-executing detection for encoded PHP in non-PHP extensions. */
 /** Static high-confidence detection of fragmented, staged PHP loaders. Never executes payloads. */
 static function fragmented_loader_signals($body){
  if(!is_string($body)||strlen($body)<8192||!preg_match('/<\?(?:php|=|\s)/i',$body))return [];
  $count=preg_match_all('/\$configBlock[0-9]{1,6}\s*=\s*[\x27\x22][A-Za-z0-9+\/=]{16,}[\x27\x22]\s*;/', $body);
  $map=(bool)preg_match('/\$configMap\s*=|resolveApplication\s*\(/i',$body);
  $stages=(bool)preg_match('/\b(?:tempnam|include|require|file_put_contents|unlink)\s*\(|\$_(?:temp|write|include|remove|make|map1|unpack)\b/i',$body);
  $ascii=(bool)preg_match('/\b(?:chr|array_map)\s*\(|\$_make\s*\(\s*array\s*\(/i',$body);
  if($count>=100 && $map && $stages && $ascii)return ['fragmented staged PHP loader: many encoded blocks, runtime function construction and staged execution'];
  return [];
 }
 static function encoded_signals($body){
  $signals=self::fragmented_loader_signals($body);
  $php_tag=(bool)preg_match('/<\?(?:php|=|\s)/i',$body);
  if(!$php_tag)return $signals;
  if(preg_match('/\beval\s*\(/i',$body) && preg_match('/\bhex2bin\s*\(|\bpack\s*\(\s*[\\\"\']H\*|\bbase64_decode\s*\(/i',$body))$signals[]='encoded payload passed to dynamic PHP evaluation';
  if(preg_match('/\beval\s*\(\s*\$[A-Za-z_][A-Za-z_0-9]*\s*\)/i',$body) && preg_match('/\bhex2bin\b/i',$body))$signals[]='hex decoding followed by variable evaluation';
  // Decode bounded long hex literals ONLY for static inspection. Never evaluate decoded code.
  if(preg_match_all('/[\"\']([a-fA-F0-9]{256,65535})[\"\']/', $body, $matches)){
   foreach(array_slice($matches[1],0,5) as $hex){
    if(strlen($hex)%2!==0)continue;
    $decoded=@hex2bin($hex);
    if(!is_string($decoded))continue;
    if(preg_match('/\b(?:curl_exec|file_get_contents|wp_remote_get)\s*\(/i',$decoded) && preg_match('/\b(?:REQUEST_URI|HTTP_USER_AGENT|HTTP_HOST|robots\.txt|sitemap\.xml)\b/i',$decoded))$signals[]='decoded payload contains remote-content/SEO-cloaking indicators';
    if(preg_match('/\b(?:eval|assert|shell_exec|passthru)\s*\(/i',$decoded))$signals[]='decoded payload contains code execution primitives';
   }
  }
  // Correlated packed loader: aliases for decoding/decompression, an opaque long
  // payload, and dynamic evaluation. Restrict to a PHP script with all three
  // properties to avoid flagging ordinary code that merely uses base64.
  $has_decoder=(bool)preg_match('/\b(?:base64_decode|hex2bin)\b/i',$body);
  $has_unpack=(bool)preg_match('/\b(?:gzuncompress|gzinflate|gzdecode)\b|Z3p1bmNvbXByZXNz|Z3ppbmZsYXRl|Z3pkZWNvZGU=/i',$body);
  $has_eval=(bool)preg_match('/\beval\s*\(/i',$body);
  $has_opaque=(bool)preg_match('/[A-Za-z0-9+\/]{700,}={0,2}/',$body);
  if($has_decoder && $has_unpack && $has_eval && $has_opaque)
   $signals[]='packed PHP loader: decoder, decompressor, dynamic evaluation and long encoded payload';
  return array_values(array_unique($signals));
 }
 static function inspect($p,$root,&$findings,&$s){$rel=self::relative($p);if($rel===''){$s['skipped']++;return;}$norm=str_replace('\\','/',$rel);$size=@filesize($p);if($size===false){$s['skipped']++;return;}$ext=strtolower(pathinfo($p,PATHINFO_EXTENSION));$php=preg_match('/\.(?:php[0-9]?|phtml|phar|inc)$/i',$p);$uploads=preg_match('~(^|/)wp-content/(?:uploads|cache|upgrade)/~i',$norm);
 // Inventory nonstandard root files independently of content signatures.
 $anomaly=self::root_anomaly($norm,$size,(bool)$php,self::benign_index($p,$norm,$size));
 if($anomaly)self::add($findings,$norm,'root_inventory',$anomaly[1],$anomaly[0]);
 // Compare official distribution files before applying heuristics; a mismatch is actionable.
 if($php && $size<=8*1024*1024){
  $expected=null;$source='';
  if(preg_match('~^(wp-admin/|wp-includes/|[^/]+\.php$)~',$norm)){
   $core=self::official_core();if(isset($core[$norm])){$expected=$core[$norm];$source='WordPress Core';}
  }elseif(preg_match('~^wp-content/plugins/([^/]+)/(.+)$~',$norm,$parts)){
   $checks=self::official_plugin($parts[1]);if(isset($checks[$parts[2]])){$expected=$checks[$parts[2]];$source='WordPress.org plugin '.$parts[1];}
  }
  if($expected!==null){$actual=@md5_file($p);$md5=is_array($expected)?($expected[0]??''):$expected;
   if(is_string($actual)&&is_string($md5)&&preg_match('/^[a-f0-9]{32}$/i',$md5)){
    if(hash_equals(strtolower($md5),strtolower($actual))){$s['verified']=($s['verified']??0)+1;return;}
    self::add($findings,$norm,'checksum_mismatch','Official '.$source.' checksum mismatch; compare with a trusted release before restoring','high');
   }
  }
 }
 if($uploads && $php && !self::benign_index($p,$norm,$size))self::add($findings,$norm,'executable_in_writable_dir','Executable-looking file in a normally writable directory','high');
 if(preg_match('~(^|/)(?:\.user\.ini|\.htaccess)$~i',$norm) && $size<262144){$body=@file_get_contents($p,false,null,0,262144);if(is_string($body)&&preg_match('/auto_prepend_file\s*=|AddHandler\s+application\/x-httpd-php/i',$body))self::add($findings,$norm,'server_config','Server configuration contains PHP execution directive; verify legitimacy','medium');}
 // Inspect executable PHP disguised as text or unknown extension, without running it.
 $text_candidate=(!$php && $size>0 && $size<=8*1024*1024 && (strpos($norm,'/')===false || in_array($ext,['txt','log','dat','bak','old','inc',''],true)));
 if($text_candidate){
  $sample=@file_get_contents($p,false,null,0,min((int)$size,8*1024*1024));
  if(is_string($sample)){
   $indicators=self::encoded_signals($sample);
   if($indicators)self::add($findings,$norm,'encoded_payload',implode('; ',$indicators),'high');
  }else{$s['skipped']++;}
 }
 if(!$php && strpos($norm,'/')===false && preg_match('/^google[a-z0-9]+\.html$/i',$norm)){
  $verification=@file_get_contents($p,false,null,0,512);
  if(is_string($verification)&&preg_match('/^google-site-verification:\s*google[a-z0-9]+\.html\s*$/i',trim($verification)))
   self::add($findings,$norm,'verification_file','Google site ownership verification file; confirm authorized owner before removing','low');
 }
 if(!$php)return;if($size>8*1024*1024){$s['skipped']++;self::add($findings,$norm,'oversized_php','PHP file larger than 8 MB; content not inspected','info');return;}$body=@file_get_contents($p,false,null,0,min((int)$size,8*1024*1024));if(!is_string($body)){$s['skipped']++;return;}$signals=[];
 if(preg_match('/\beval\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\(/i',$body))$signals[]='obfuscated evaluation';
 $signals=array_merge($signals,self::encoded_signals($body));
 if(preg_match('/\b(?:shell_exec|passthru|system|exec)\s*\(\s*\$_(?:GET|POST|REQUEST)/i',$body))$signals[]='request-controlled shell execution';
 if(preg_match('/\b(?:file_put_contents|fwrite)\s*\([^;]{0,200}\$_(?:GET|POST|REQUEST)/is',$body))$signals[]='request-controlled file write';
 if(preg_match('/\b(?:assert|preg_replace)\s*\(\s*\$_(?:GET|POST|REQUEST)/i',$body))$signals[]='request-controlled dynamic evaluation';
 if(preg_match('/\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST)/i',$body))$signals[]='request-controlled PHP inclusion';
 if(preg_match('/\b(?:base64_decode|gzinflate|str_rot13)\s*\(/i',$body)&&preg_match('/\b(?:eval|assert|create_function)\s*\(/i',$body))$signals[]='obfuscation combined with dynamic execution';
 // Do not flag unrelated remote fetch and eval calls in a large legitimate library.
 // Correlation requires direct data flow and is not implemented in this build.
 
 if(strpos($norm,'/')===false && self::seo_tamper($body))self::add($findings,$norm,'seo_tamper','Root PHP writes robots.txt and Google verification files; likely unauthorized SEO manipulation','high');
 if($signals)self::add($findings,$norm,'heuristic',implode('; ',$signals),count($signals)>1?'high':'medium');
 }
 static function page(){
  if(!current_user_can('manage_options'))return;
  $s=get_option(self::STATE,[]);$items=get_option(self::FINDINGS,[]);if(!is_array($items))$items=[];
  echo '<div class="wrap"><h1>WP Sentinel X — Full Site Scan</h1><p>Scan is read-only by default. Only high-confidence encoded payloads and correlated SEO-tampering scripts in standalone root files can be manually quarantined after confirmation. Other findings require review. Quarantine preserves evidence outside the document root when hosting permissions allow.</p>';
  $notice=get_transient('wpsx_full_notice_'.get_current_user_id());if($notice){echo '<div class="notice notice-info"><p>'.esc_html($notice).'</p></div>';delete_transient('wpsx_full_notice_'.get_current_user_id());}
  echo '<button class="button button-primary" id="wpsx-full-start">Start full site scan</button> <span id="wpsx-full-status">'.esc_html(is_array($s)&&!empty($s['visited'])?($s['visited'].' files examined previously'):'Not started').'</span><h2>Findings</h2><table class="widefat striped"><thead><tr><th>Severity</th><th>File</th><th>Reason</th><th>Action</th></tr></thead><tbody id="wpsx-full-findings">';
  foreach(array_slice($items,0,200) as $f){echo '<tr><td>'.esc_html($f['severity']).'</td><td><code>'.esc_html($f['path']).'</code></td><td>'.esc_html($f['detail']).'</td><td>'.self::action_html($f).'</td></tr>';}
  echo '</tbody></table>';
  self::quarantine_manager();
  echo '<p>Do not quarantine legitimate WordPress, Wordfence, plugin, or theme files based on severity alone. The scanner does not inspect the database or hosting accounts.</p></div>';
  $nonce=wp_create_nonce('wpsx_full_scan');$ajax=admin_url('admin-ajax.php');
  echo '<script>(function(){const b=document.getElementById("wpsx-full-start"),s=document.getElementById("wpsx-full-status");const endpoint='.wp_json_encode($ajax).',nonce='.wp_json_encode($nonce).';async function call(action){const p=new URLSearchParams({action,nonce});const r=await fetch(endpoint,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:p});const j=await r.json();if(!j.success)throw Error(typeof j.data==="string"?j.data:"Scan request failed");return j.data;}async function refreshResults(){window.location.reload();}async function run(){b.disabled=true;try{let d=await call("wpsx_full_start");while(true){d=await call("wpsx_full_step");s.textContent=d.visited+" files checked, "+(d.verified||0)+" officially verified, "+d.dirs+" directories, "+d.findings+" findings, "+d.skipped+" skipped"+(d.error?" — "+d.error:"");if(d.finished){await refreshResults();break;}}}catch(e){s.textContent="Scan interrupted: "+e.message;}finally{b.disabled=false;}}b.addEventListener("click",run);})();</script>';
 }
 static function quarantine_manager(){
  $dir=self::evidence_dir();$root=self::root();$records=get_option(self::QUARANTINE,[]);if(!is_array($records))$records=[];
  echo '<h2>Quarantine Manager</h2><p>Evidence location (actual server path): <code>'.esc_html($dir?:'Unavailable').'</code></p>';
  echo '<p>Evidence directory: <strong>'.esc_html($dir&&is_dir($dir)?'Exists':'Not found or inaccessible').'</strong>. WordPress document root: <code>'.esc_html($root?:'Unavailable').'</code>.</p>';
  echo '<p>Evidence files are outside the document root when possible. Restoring a quarantined malicious file may make it accessible again. Do not restore unless needed for controlled investigation.</p>';
  echo '<table class="widefat striped"><thead><tr><th>Original</th><th>Evidence file</th><th>SHA-256</th><th>Time (UTC)</th><th>Status</th><th>Action</th></tr></thead><tbody>';
  foreach(array_reverse($records) as $rec){$id=$rec['id']??'';$rel=$rec['original']??'';$hash=$rec['sha256']??'';
   $exists=$dir&&is_file($dir.DIRECTORY_SEPARATOR.$id)&&!is_link($dir.DIRECTORY_SEPARATOR.$id);
   $valid=$exists&&is_string($hash)&&preg_match('/^[a-f0-9]{64}$/D',$hash)&&hash_equals($hash,(string)@hash_file('sha256',$dir.DIRECTORY_SEPARATOR.$id));
   echo '<tr><td><code>'.esc_html($rel).'</code></td><td><code>'.esc_html($id).'</code></td><td><code>'.esc_html(substr((string)$hash,0,16)).'...</code></td><td>'.esc_html(gmdate('Y-m-d H:i:s',(int)($rec['time']??0))).'</td><td>'.esc_html(($rec['status']??'unknown').($valid?' / evidence verified':' / evidence missing or invalid')).'</td><td>';
   if(($rec['status']??'')==='quarantined'&&$valid&&!file_exists($root.DIRECTORY_SEPARATOR.$rel)){
    echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'" onsubmit="return confirm(\'This restores a file flagged as malicious. Continue?\');"><input type="hidden" name="action" value="wpsx_full_restore"><input type="hidden" name="evidence_id" value="'.esc_attr($id).'">';wp_nonce_field('wpsx_full_restore');echo '<button type="submit" class="button">Restore (dangerous)</button></form>';
   }else echo '—';echo '</td></tr>';
  }
  if(!$records)echo '<tr><td colspan="6">No quarantine records yet. Earlier quarantines may predate this manager; check the evidence directory path above.</td></tr>';
  echo '</tbody></table>';
 }
 static function action_html($f){
  if(!in_array(($f['type']??''),['encoded_payload','seo_tamper'],true)||($f['severity']??'')!=='high')return 'Review only';
  $rel=$f['path']??'';if(!is_string($rel)||strpos($rel,'/')!==false)return 'Review only';
  $root=self::root();$p=$root.DIRECTORY_SEPARATOR.$rel;
  if(!is_file($p)||is_link($p)||!is_readable($p))return 'File unavailable';
  $hash=@hash_file('sha256',$p);if(!$hash)return 'File unavailable';
  $out='<form method="post" action="'.esc_url(admin_url('admin-post.php')).'" onsubmit="return confirm(\'Quarantine this suspicious standalone file? Evidence will be saved outside webroot.\');">';
  $out.='<input type="hidden" name="action" value="wpsx_full_quarantine">';
  $out.='<input type="hidden" name="path" value="'.esc_attr($rel).'"><input type="hidden" name="sha256" value="'.esc_attr($hash).'">';
  $out.=wp_nonce_field('wpsx_full_quarantine','_wpnonce',true,false);
  return $out.'<button class="button button-secondary" type="submit">Quarantine (preserve copy)</button></form>';
 }
 static function menu(){add_submenu_page('wpsx','Full Site Scan','Full Site Scan','manage_options','wpsx_full_scan',[__CLASS__,'page']);}
}
WPSX_Full_Scan::init();
