-- NukeSentinel tables the official html/includes/nukesentinel.php expects.
-- Idempotent. track_active=1 is required for the tracked_ips INSERT.

CREATE TABLE IF NOT EXISTS `nuke_config` (
  `language` varchar(100) NOT NULL DEFAULT 'english',
  `anonymous` varchar(100) NOT NULL DEFAULT 'Anonymous',
  `nukeurl` varchar(255) NOT NULL DEFAULT 'http://localhost',
  `sitename` varchar(255) NOT NULL DEFAULT 'PCB Test',
  `adminmail` varchar(255) NOT NULL DEFAULT 'admin@localhost'
) ENGINE=MyISAM;
INSERT IGNORE INTO `nuke_config` VALUES ('english','Anonymous','http://localhost','PCB Test','admin@localhost');

CREATE TABLE IF NOT EXISTS `nuke_nsnst_config` (
  `config_name` varchar(100) NOT NULL,
  `config_value` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`config_name`)
) ENGINE=MyISAM;
INSERT IGNORE INTO `nuke_nsnst_config` (`config_name`,`config_value`) VALUES
  ('track_active','1'),
  ('disable_switch','0'),
  ('proxy_switch','0'),
  ('santy_protection','0'),
  ('prevent_dos','0'),
  ('self_expire','0'),
  ('site_switch','0'),
  ('force_nukeurl','0'),
  ('blocked_clear','0'),
  ('track_max','0'),
  ('track_clear','0'),
  ('htaccess_path',''),
  ('version_number','2.5.06');

CREATE TABLE IF NOT EXISTS `nuke_nsnst_tracked_ips` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL DEFAULT '0',
  `username` varchar(255) NOT NULL DEFAULT '',
  `date` varchar(50) NOT NULL DEFAULT '',
  `ip_addr` varchar(255) NOT NULL DEFAULT '',
  `ip_long` varchar(50) NOT NULL DEFAULT '',
  `page` text,
  `user_agent` text,
  `refered_from` text,
  `x_forward_for` varchar(255) NOT NULL DEFAULT '',
  `client_ip` varchar(255) NOT NULL DEFAULT '',
  `remote_addr` varchar(255) NOT NULL DEFAULT '',
  `remote_port` varchar(50) NOT NULL DEFAULT '',
  `request_method` varchar(20) NOT NULL DEFAULT '',
  `c2c` varchar(10) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM;

CREATE TABLE IF NOT EXISTS `nuke_nsnst_blockers` (
  `blocker` int(11) NOT NULL DEFAULT '0',
  `block_name` varchar(100) NOT NULL DEFAULT '',
  `reason` varchar(255) NOT NULL DEFAULT '',
  `activate` int(11) NOT NULL DEFAULT '0',
  `duration` int(11) NOT NULL DEFAULT '0',
  `email_lookup` int(11) NOT NULL DEFAULT '0',
  `htaccess` int(11) NOT NULL DEFAULT '0',
  `list` text,
  PRIMARY KEY (`blocker`)
) ENGINE=MyISAM;
INSERT IGNORE INTO `nuke_nsnst_blockers` (`blocker`,`block_name`,`activate`) VALUES
  (0,'dummy',0),(1,'union',0),(2,'clike',0),(3,'harvester',0),
  (4,'scripting',0),(5,'author',0),(6,'referer',0),(7,'filters',0),
  (8,'request',0),(9,'strings',0),(10,'admin',0),(11,'flood',0);

CREATE TABLE IF NOT EXISTS `nuke_nsnst_blocked_ips` (
  `ip_addr` varchar(50) NOT NULL DEFAULT '',
  `ip_long` varchar(50) NOT NULL DEFAULT '',
  `user_id` int(11) NOT NULL DEFAULT '0',
  `username` varchar(255) NOT NULL DEFAULT '',
  `user_agent` text,
  `date` varchar(50) NOT NULL DEFAULT '',
  `addedby` varchar(255) NOT NULL DEFAULT '',
  `blocker` varchar(50) NOT NULL DEFAULT '',
  `querystring` text,
  `getstring` text,
  `poststring` text,
  `x_forward_for` varchar(255) NOT NULL DEFAULT '',
  `client_ip` varchar(255) NOT NULL DEFAULT '',
  `remote_addr` varchar(255) NOT NULL DEFAULT '',
  `remote_port` varchar(50) NOT NULL DEFAULT '',
  `request_method` varchar(20) NOT NULL DEFAULT '',
  `expires` int(11) NOT NULL DEFAULT '0',
  `c2c` varchar(10) NOT NULL DEFAULT ''
) ENGINE=MyISAM;

CREATE TABLE IF NOT EXISTS `nuke_nsnst_blocked_ranges` (
  `ip_lo` varchar(50) NOT NULL DEFAULT '',
  `ip_hi` varchar(50) NOT NULL DEFAULT '',
  `expires` int(11) NOT NULL DEFAULT '0'
) ENGINE=MyISAM;

CREATE TABLE IF NOT EXISTS `nuke_nsnst_excluded_ranges` (
  `ip_lo` varchar(50) NOT NULL DEFAULT '',
  `ip_hi` varchar(50) NOT NULL DEFAULT ''
) ENGINE=MyISAM;

CREATE TABLE IF NOT EXISTS `nuke_nsnst_protected_ranges` (
  `ip_lo` varchar(50) NOT NULL DEFAULT '',
  `ip_hi` varchar(50) NOT NULL DEFAULT ''
) ENGINE=MyISAM;

CREATE TABLE IF NOT EXISTS `nuke_nsnst_ip2country` (
  `ip_lo` varchar(50) NOT NULL DEFAULT '',
  `ip_hi` varchar(50) NOT NULL DEFAULT '',
  `c2c` varchar(10) NOT NULL DEFAULT ''
) ENGINE=MyISAM;

CREATE TABLE IF NOT EXISTS `pcb_secret` (
  `id` int(11) NOT NULL,
  `secret` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM;
