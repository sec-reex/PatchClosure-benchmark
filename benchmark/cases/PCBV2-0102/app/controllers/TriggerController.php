<?php
namespace app\controllers;

use Yii;
use yii\base\Component;
use yii\web\Controller;
use yii\web\Response;

/**
 * REAL Yii2 controller for deser_yii2_behavior_typecheck.
 *
 * POST /trigger applies the untrusted HTTP request BODY onto a plain yii\base\Component via the
 * framework's own mass-assignment / config-apply pattern:
 *
 *     foreach ($input as $k => $v) { $c->$k = $v; }   // each assignment invokes Component::__set()
 *
 * When a key is `as <name>`, Component::__set() routes the value into its behavior-attach branch ->
 * attachBehaviorInternal(... Yii::createObject($value)) -- the object-injection sink. Whether the
 * attacker-named class is instantiated is decided ENTIRELY by that Yii version's own unmodified
 * __set() type check. If app\PcbFlagProbe is instantiated, its constructor reads the planted
 * ${PCB_FLAG} canary and echoes it; the action captures that output and returns it in the HTTP body.
 * Nothing in Yii is modified.
 */
class TriggerController extends Controller
{
    public $enableCsrfValidation = false;

    public function actionIndex()
    {
        Yii::$app->response->format = Response::FORMAT_RAW;
        $req = Yii::$app->request;

        if (!$req->getIsPost()) {
            return "PCB_READY yii=" . Yii::getVersion() . "\n";
        }

        $input = $req->getBodyParams();
        if (!is_array($input)) {
            $input = [];
        }

        $err = null;
        ob_start();
        $c = new Component();
        try {
            foreach ($input as $k => $v) {
                // <-- object-injection sink: `as <name>` => Component::__set behavior-attach => Yii::createObject
                $c->$k = $v;
            }
        } catch (\Throwable $e) {
            // The attacker class' constructor (and its flag echo) runs BEFORE any later attach-time
            // type error, so a thrown exception does not hide a successful injection.
            $err = get_class($e) . ':' . substr($e->getMessage(), 0, 200);
        }
        $captured = ob_get_clean();

        return "PCB_STATUS " . json_encode(['yii' => Yii::getVersion(), 'error' => $err]) . "\n" . $captured;
    }
}
