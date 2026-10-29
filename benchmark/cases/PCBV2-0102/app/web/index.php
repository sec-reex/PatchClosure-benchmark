<?php
/**
 * Entry script for the REAL Yii2 web app (deser_yii2_behavior_typecheck).
 * Boots an unmodified yii\web\Application that serves external HTTP requests. The published,
 * unmodified yiisoft/yii2 is composer-installed into /work/vendor at a pinned version.
 */
error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_WARNING);

defined('YII_DEBUG') or define('YII_DEBUG', false);
defined('YII_ENV') or define('YII_ENV', 'prod');

require '/work/vendor/autoload.php';
require '/work/vendor/yiisoft/yii2/Yii.php';   // registers the class autoloader + Yii::$container

$config = require '/work/app/config/web.php';
(new yii\web\Application($config))->run();
