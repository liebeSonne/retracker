<?php

define('TIMENOW', time());
require('./config.php');

// ----------------------------------------------------------------------------
// Initialization
//
// Cache
switch ($tr_cfg['tr_cache_type'])
{
    case 'sqlite':
        $tr_cache = new cache_sqlite($tr_cfg['tr_cache']['sqlite']);
        break;
    default:
        $tr_cache = new cache_common();
}

// DB
switch ($tr_cfg['tr_db_type'])
{
    case 'mysql':
        $db = new mysql_common($tr_cfg['tr_db']['mysql']);
        break;
    case 'sqlite':
        $default_cfg = array(
            'db_file_path' => '/dev/shm/tr.db.sqlite',
            'table_name'   => 'tracker',
            'table_schema' => 'CREATE TABLE tracker (
                                 info_hash   CHAR(20),
                                 ip          CHAR(8),
                                 port        INT,
                                 update_time INT,
                                 PRIMARY KEY (info_hash, ip, port)
                               )',
            'pconnect'     => true,
            'con_required' => true,
            'log_name'     => 'SQLite',
        );
        $db = new sqlite_common(array_merge($default_cfg, $tr_cfg['tr_db']['sqlite']));
        break;
    default:
        trigger_error('unsupported db type', E_USER_ERROR);
}

// Garbage collector
if (!empty($_GET[$tr_cfg['run_gc_key']]))
{
    $announce_interval = max(intval($tr_cfg['announce_interval']), 60);
    $expire_factor     = max(floatval($tr_cfg['peer_expire_factor']), 2);
    $peer_expire_time  = TIMENOW - floor($announce_interval * $expire_factor);

    $db->query("DELETE FROM tracker WHERE update_time < $peer_expire_time");

    if (method_exists($tr_cache, 'gc'))
    {
        $changes = $tr_cache->gc();
    }

    die();
}

// Recover info_hash
if (isset($_GET['?info_hash']) && !isset($_GET['info_hash']))
{
    $_GET['info_hash'] = $_GET['?info_hash'];
}

// Input var names
// String
$input_vars_str = array(
    'info_hash',
    'event',
);
// Numeric
$input_vars_num = array(
    'port',
);

// Init received data
// String
foreach ($input_vars_str as $var_name)
{
    $$var_name = isset($_GET[$var_name]) ? (string) $_GET[$var_name] : null;
}
// Numeric
foreach ($input_vars_num as $var_name)
{
    $$var_name = isset($_GET[$var_name]) ? (float) $_GET[$var_name] : null;
}

// Verify required request params (info_hash, port)
if (!isset($info_hash) || strlen($info_hash) != 20)
{
    msg_die('Invalid info_hash');
}
if (!isset($port) || $port < 0 || $port > 0xFFFF)
{
    msg_die('Invalid port');
}

// IP
$ip = $_SERVER['REMOTE_ADDR'];

if (!$tr_cfg['ignore_reported_ip'] && isset($_GET['ip']) && $ip !== $_GET['ip'])
{
    if (!$tr_cfg['verify_reported_ip'])
    {
        $ip = $_GET['ip'];
    }
    else if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && preg_match_all('#\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#', $_SERVER['HTTP_X_FORWARDED_FOR'], $matches))
    {
        foreach ($matches[0] as $x_ip)
        {
            if ($x_ip === $_GET['ip'])
            {
                if (!$tr_cfg['allow_internal_ip'] && preg_match("#^(10|172\.16|192\.168)\.#", $x_ip))
                {
                    break;
                }
                $ip = $x_ip;
                break;
            }
        }
    }
}
// Check that IP format is valid
if (!verify_ip($ip))
{
    msg_die("Invalid IP: $ip");
}
// Convert IP to HEX format
$ip_sql = encode_ip($ip);

// ----------------------------------------------------------------------------
// Start announcer
//
$info_hash_sql = rtrim($db->escape($info_hash), ' ');

// Stopped event
if ($event === 'stopped')
{
    $db->query("DELETE FROM tracker WHERE info_hash = '$info_hash_sql' AND ip = '$ip_sql' AND port = $port");
    die();
}

// Update peer info
$db->query("REPLACE INTO tracker (info_hash, ip, port, update_time) VALUES ('$info_hash_sql', '$ip_sql', $port, ". TIMENOW .")");

// Get cached output
if (!$output = $tr_cache->get(PEERS_LIST_PREFIX . $info_hash))
{
    // Retrieve peers
    $peers        = '';
    $ann_interval = $tr_cfg['announce_interval'] + mt_rand(0, 600);

    $rowset = $db->fetch_rowset("
        SELECT ip, port
        FROM tracker
        WHERE info_hash = '$info_hash_sql'
        ORDER BY ". $db->random_fn ."
        LIMIT ". (int) $tr_cfg['numwant'] ."
    ");

    foreach ($rowset as $peer)
    {
        $peers .= pack('Nn', ip2long(decode_ip($peer['ip'])), $peer['port']);
    }

    $output = array(
        'interval'     => (int) $ann_interval,
        'min interval' => (int) $ann_interval,
        'peers'        => $peers,
    );

    $peers_list_cached = $tr_cache->set(PEERS_LIST_PREFIX . $info_hash, $output, PEERS_LIST_EXPIRE);
}

// Return data to client
echo bencode($output);

exit;

// ----------------------------------------------------------------------------
// Functions
//
function msg_die ($msg)
{
    $output = bencode(array(
        'min interval'   => (int)    1800,
        'failure reason' => (string) $msg,
    ));
    die($output);
}

function encode_ip ($ip)
{
    $d = explode('.', $ip);
    return sprintf('%02x%02x%02x%02x', $d[0], $d[1], $d[2], $d[3]);
}

function decode_ip ($ip)
{
    return long2ip((int) "0x{$ip}");
}

function verify_ip ($ip)
{
    return preg_match('#^(\d{1,3}\.){3}\d{1,3}$#', $ip);
}

function str_compact ($str)
{
    return preg_replace('#\s+#', ' ', trim($str));
}

// bencode: based on OpenTracker [http://whitsoftdev.com/opentracker]
function bencode ($var)
{
    if (is_string($var))
    {
        return strlen($var) .':'. $var;
    }
    else if (is_int($var))
    {
        return 'i'. $var .'e';
    }
    else if (is_float($var))
    {
        return 'i'. sprintf('%.0f', $var) .'e';
    }
    else if (is_array($var))
    {
        if (count($var) == 0)
        {
            return 'de';
        }
        else
        {
            $assoc = false;

            foreach ($var as $key => $val)
            {
                if (!is_int($key))
                {
                    $assoc = true;
                    break;
                }
            }

            if ($assoc)
            {
                ksort($var, SORT_REGULAR);
                $ret = 'd';

                foreach ($var as $key => $val)
                {
                    $ret .= bencode($key) . bencode($val);
                }
                return $ret .'e';
            }
            else
            {
                $ret = 'l';

                foreach ($var as $val)
                {
                    $ret .= bencode($val);
                }
                return $ret .'e';
            }
        }
    }
    else
    {
        trigger_error('bencode error: wrong data type', E_USER_ERROR);
    }
}

// Cache
class cache_common
{
    var $used = false;
    /**
    * Returns value of variable
    */
    function get ($name)
    {
        return false;
    }
    /**
    * Store value of variable
    */
    function set ($name, $value, $ttl = 0)
    {
        return false;
    }
    /**
    * Remove variable
    */
    function rm ($name)
    {
        return false;
    }
}

class cache_sqlite extends cache_common
{
    var $used = true;
    var $db   = null;
    var $cfg  = array(
                  'db_file_path' => '/dev/shm/tr.cache.sqlite',
                  'table_name'   => 'cache',
                  'table_schema' => 'CREATE TABLE cache (
                                       cache_name        VARCHAR(255),
                                       cache_expire_time INT,
                                       cache_value       TEXT,
                                       PRIMARY KEY (cache_name)
                                     )',
                  'pconnect'     => true,
                  'con_required' => true,
                  'log_name'     => 'CACHE',
                );

    function __construct($cfg)
    {
        $this->cfg = array_merge($this->cfg, $cfg);
        $this->db = new sqlite_common($this->cfg);
    }

    function get ($name)
    {
        $result = $this->db->query("
            SELECT cache_value
            FROM ". $this->cfg['table_name'] ."
            WHERE cache_name = '". SQLite3::escapeString($name) ."'
                AND cache_expire_time > ". TIMENOW ."
            LIMIT 1
        ");

        $row = $result->fetchArray(SQLITE3_ASSOC);
        $cache_value = $row ? $row['cache_value'] : '';
        return ($result AND $cache_value) ? unserialize($cache_value) : false;
    }

    function set ($name, $value, $ttl = 86400)
    {
        $name   = SQLite3::escapeString($name);
        $expire = TIMENOW + $ttl;
        $value  = SQLite3::escapeString(serialize($value));

        $result = $this->db->query("
            REPLACE INTO ". $this->cfg['table_name'] ."
                (cache_name, cache_expire_time, cache_value)
            VALUES
                ('$name', '$expire', '$value')
        ");

        return (bool) $result;
    }

    function rm ($name)
    {
        $result = $this->db->query("
            DELETE FROM ". $this->cfg['table_name'] ."
            WHERE cache_name = '". SQLite3::escapeString($name) ."'
        ");

        return (bool) $result;
    }

    function gc ($expire_time = TIMENOW)
    {
        $result = $this->db->query("
            DELETE FROM ". $this->cfg['table_name'] ."
            WHERE cache_expire_time < $expire_time
        ");

        return ($result) ? ($this->db->dbh->changes()) : 0;
    }
}

class sqlite_common
{
    var $cfg = array(
                 'db_file_path' => 'sqlite.db',
                 'table_name'   => 'table_name',
                 'table_schema' => 'CREATE TABLE table_name (...)',
                 'pconnect'     => true,
                 'con_required' => true,
                 'log_name'     => 'SQLite',
               );
    var $dbh                    = null;
    var $table_create_attempts  = 0;
    var $random_fn              = 'random()';

    function __construct($cfg)
    {
        if (!class_exists("SQLite3")) die('Error: SQLite3 extension not installed');
        $this->cfg = array_merge($this->cfg, $cfg);
    }

    function init ()
    {
        $sqlite_error = null;
        try {
            $this->dbh = new SQLite3($this->cfg['db_file_path']);
        } catch (Exception $e) {
            $sqlite_error = $e->getMessage();
        }

        if (!$this->dbh && $this->cfg['con_required'])
        {
            trigger_error($sqlite_error, E_USER_ERROR);
        }
    }

    function create_table ()
    {
        $this->table_create_attempts++;
        $result = $this->dbh->query($this->cfg['table_schema']);
        $msg = ($result) ? "{$this->cfg['table_name']} table created" : $this->get_error_msg();
        trigger_error($msg, E_USER_WARNING);
        return $result;
    }

    function query ($query, $type = 'unbuffered')
    {
        if (!$this->dbh) $this->init();

        if (!$result = $this->dbh->query($query))
        {
            if (!$this->table_create_attempts && !$this->dbh->exec("PRAGMA table_info({$this->cfg['table_name']})"))
            {
                if ($this->create_table())
                {
                    $result = $this->dbh->query($query);
                }
            }
            if (!$result)
            {
                $this->trigger_error($this->get_error_msg());
            }
        }

        return $result;
    }

    function fetch_row ($query, $type = 'unbuffered')
    {
        $result = $this->dbh->query($query);
        return $result ? $result->fetchArray(SQLITE3_ASSOC) : false;
    }

    function fetch_rowset ($query, $type = 'unbuffered')
    {
        $result = $this->dbh->query($query);
        $rows = array();
        if ($result) {
            while($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $rows[] = $row;
            }
        }
        return $rows;
    }

    function escape ($str)
    {
        return SQLite3::escapeString($str);
    }

    function get_error_msg ()
    {
        return 'SQLite error #'. ($err_code = $this->dbh->lastErrorCode()) .': '. $this->dbh->lastErrorMsg();
    }

    function trigger_error ($msg = 'DB Error')
    {
        if (error_reporting()) trigger_error($msg, E_USER_ERROR);
    }
}

class mysql_common
{
    var $cfg = array(
                 'dbhost'   => '',
                 'dbuser'   => '',
                 'dbpasswd' => '',
                 'dbname'   => '',
                 'pconnect' => false,
                 'log_name' => 'MySQL',
               );
    var $dbh       = null;
    var $random_fn = 'RAND()';

    function __construct($cfg)
    {
        $this->cfg = array_merge($this->cfg, $cfg);
    }

    function init ()
    {
        // Connect
        $dbhost = ($this->cfg['pconnect']) ? 'p:'.$this->cfg['dbhost'] : $this->cfg['dbhost'];
        if (@!$this->dbh = mysqli_connect($dbhost, $this->cfg['dbuser'], $this->cfg['dbpasswd']))
        {
            trigger_error($this->get_error_msg(), E_USER_ERROR);
        }
        register_shutdown_function(array(&$this, 'disconnect'));

        // Select DB
        if (!mysqli_select_db($this->dbh, $this->cfg['dbname']))
        {
            trigger_error($this->get_error_msg(), E_USER_ERROR);
        }
        // Set charset
        if (!$this->query("SET NAMES cp1251"))
        {
            trigger_error("Could not set charset cp1251", E_USER_ERROR);
        }
    }

    function disconnect ()
    {
        if ($this->dbh) mysqli_close($this->dbh);
        $this->dbh = $this->selected_db = null;
    }

    function query ($query, $type = 'unbuffered')
    {
        if (!$this->dbh) $this->init();

        if ($type === 'unbuffered') {
            $result = mysqli_query($this->dbh, $query, MYSQLI_USE_RESULT);
        } else {
            $result = mysqli_query($this->dbh, $query);
        }
        if (!$result)
        {
            $this->trigger_error($this->get_error_msg());
        }
        return $result;
    }

    function fetch_row ($query, $type = 'unbuffered')
    {
        $result = $this->query($query, $type);
        $row = $result ? mysqli_fetch_array($result, MYSQLI_ASSOC) : false;
        if ($result && $type === 'unbuffered') {
            mysqli_free_result($result);
        }
        return $row;
    }

    function fetch_rowset ($query, $type = 'unbuffered')
    {
        $rowset = array();
        $result = $this->query($query, $type);
        if ($result)
        {
            while ($row = mysqli_fetch_array($result, MYSQLI_ASSOC)) $rowset[] = $row;
            if ($type === 'unbuffered') {
                mysqli_free_result($result);
            }
        }
        return $rowset;
    }

    function escape ($str)
    {
        if (!$this->dbh) $this->init();
        return mysqli_real_escape_string($this->dbh, $str);
    }

    function get_error_msg ()
    {
        return ($this->dbh) ? 'MySQL error #'. mysqli_errno($this->dbh) .': '. mysqli_error($this->dbh) : 'not connected';
    }

    function trigger_error ($msg = 'DB Error')
    {
        if (error_reporting()) trigger_error($msg, E_USER_ERROR);
    }
}
