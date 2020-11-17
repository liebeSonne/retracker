<?php

error_reporting(E_ALL);                            // Set php error reporting mode
set_magic_quotes_runtime(0);                       // Disable magic_quotes_runtime

// Tracker config
$tr_cfg = array();

// Garbage collector (run this script in cron each 5 minutes with '?run_gc=1' e.g. http://yoursite.com/announce.php?run_gc=1)
$tr_cfg['run_gc_key'] = 'run_gc';

$tr_cfg['announce_interval']  = 1800;              // sec, min = 60
$tr_cfg['peer_expire_factor'] = 2.5;               // min = 2; Consider a peer dead if it has not announced in a number of seconds equal to this many times the calculated announce interval at the time of its last announcement
$tr_cfg['numwant']            = 50;                // number of peers being sent to client
$tr_cfg['ignore_reported_ip'] = true;              // Ignore IP reported by client
$tr_cfg['verify_reported_ip'] = false;             // Verify IP reported by client against $_SERVER['HTTP_X_FORWARDED_FOR']
$tr_cfg['allow_internal_ip']  = true;              // Allow internal IP (10.xx.. etc.)

// DB
$tr_cfg['tr_db_type'] = 'mysql';                   // Available db types: sqlite, mysql

// DB - MySQL
$tr_cfg['tr_db']['mysql'] = array(
    'dbhost'   => 'localhost',
    'dbuser'   => '',
    'dbpasswd' => '',
    'dbname'   => '',
    'pconnect' => false,
    'log_name' => 'MySQL',
);

// DB - SQLite
$tr_cfg['tr_db']['sqlite'] = array(
    'db_file_path' => '/dev/shm/tr.db.sqlite',       // preferable on tmpfs
);

// Cache
$tr_cfg['tr_cache_type'] = 'none';                 // Available cache types: none, sqlite

$tr_cfg['tr_cache']['sqlite'] = array(
    'db_file_path' => '/dev/shm/tr.cache.sqlite',    // preferable on tmpfs
);

define('PEERS_LIST_PREFIX', '');
define('PEERS_LIST_EXPIRE', round(0.7 * $tr_cfg['announce_interval']));  // sec
