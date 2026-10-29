<?php
namespace app;

/**
 * A LEGITIMATE yii\base\Behavior subclass. It exists only to satisfy V1's (2.0.50)
 * type check: the CVE-2024-4990 fix in yii\base\Component::__set() checks
 * `is_subclass_of($value['class'], Behavior::class)`. Naming this real Behavior
 * subclass in the `class` key makes that check pass -- while the CVE-2024-58136
 * residual steers Yii::createObject() to instantiate a DIFFERENT class via `__class`.
 * (Any real Behavior subclass, e.g. a framework yii\behaviors\* class, would work
 * identically; a local one keeps the app self-contained and version-agnostic.)
 */
class PcbLegitBehavior extends \yii\base\Behavior
{
}
