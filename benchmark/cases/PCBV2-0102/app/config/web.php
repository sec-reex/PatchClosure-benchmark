<?php
/**
 * Minimal REAL Yii2 web-application config for deser_yii2_behavior_typecheck.
 * A plain, unmodified Yii2 app: it routes external HTTP requests to app\controllers\TriggerController,
 * whose POST /trigger action mass-assigns the request BODY onto a yii\base\Component via __set()
 * (the config-apply / mass-assignment pattern the CVE exploits). Nothing in Yii is modified.
 */
return [
    'id' => 'pcb-yii2',
    'basePath' => '/work/app',
    'controllerNamespace' => 'app\\controllers',
    'aliases' => [
        '@app' => '/work/app',
    ],
    'components' => [
        'request' => [
            // static, benchmark-only; the app reads no cookies -- present just to satisfy web\Request.
            'cookieValidationKey' => 'pcb-benchmark-static-key',
            // benchmark driver posts JSON directly; no browser CSRF token flow.
            'enableCsrfValidation' => false,
            'parsers' => [
                'application/json' => 'yii\\web\\JsonParser',
            ],
        ],
        'urlManager' => [
            'enablePrettyUrl' => true,
            'showScriptName' => false,
        ],
    ],
];
