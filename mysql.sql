CREATE TABLE `tracker` (
  `info_hash` char(20) character set cp1251 collate cp1251_bin NOT NULL,
  `ip` char(8) character set cp1251 collate cp1251_bin NOT NULL,
  `port` smallint(5) unsigned NOT NULL default '0',
  `update_time` int(11) NOT NULL default '0',
  PRIMARY KEY  USING BTREE (`info_hash`,`ip`,`port`)
) ENGINE=MEMORY DEFAULT CHARSET=cp1251;
