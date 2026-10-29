<?php
/**
 * Configure the REAL Craft app so the public GraphQL schema exposes an
 * asset-upload mutation, using Craft's OWN service layer (no source edits):
 *   - a Local asset filesystem writing to web/uploads (public URLs on),
 *   - an asset Volume bound to it,
 *   - the PUBLIC GraphQL schema scoped to read + save that volume
 *     (so `save_<handle>_Asset(_file:{url}) ...` runs for anonymous callers).
 *
 * Idempotent: safe to re-run on every boot.
 */

// Bootstrap Craft exactly like the real `craft` console binary (defines CRAFT_BASE_PATH /
// CRAFT_VENDOR_PATH, loads the autoloader + dotenv; compose env vars win via getenv()).
require '/app/bootstrap.php';

/** @var \craft\console\Application $app */
$app = require CRAFT_VENDOR_PATH . '/craftcms/cms/bootstrap/console.php';

use craft\fs\Local;
use craft\models\Volume;

function fail(string $msg): void
{
    fwrite(STDERR, "[pcb_setup] FAIL: $msg\n");
    exit(1);
}

$publicUrl = rtrim(getenv('CRAFT_PUBLIC_URL') ?: 'http://localhost', '/');

// ---- 1. asset filesystem ----
$fsSvc = Craft::$app->getFs();
$fs = $fsSvc->getFilesystemByHandle('pcbfs');
if (!$fs) {
    $fs = new Local();
    $fs->name = 'PCB Uploads';
    $fs->handle = 'pcbfs';
    $fs->hasUrls = true;
    $fs->url = $publicUrl . '/uploads';
    $fs->path = '@webroot/uploads';
    if (!$fsSvc->saveFilesystem($fs)) {
        fail('filesystem: ' . json_encode($fs->getErrors()));
    }
    echo "[pcb_setup] created filesystem pcbfs\n";
}

// ---- 2. asset volume ----
$volSvc = Craft::$app->getVolumes();
$vol = $volSvc->getVolumeByHandle('pcbvol');
if (!$vol) {
    $vol = new Volume();
    $vol->name = 'PCB';
    $vol->handle = 'pcbvol';
    $vol->setFsHandle('pcbfs');
    if (!$volSvc->saveVolume($vol)) {
        fail('volume: ' . json_encode($vol->getErrors()));
    }
    $vol = $volSvc->getVolumeByHandle('pcbvol');
    echo "[pcb_setup] created volume pcbvol\n";
}

// Make sure the volume has a root (top) folder so asset uploads have a target. saveVolume()
// normally creates it; ensure it exists idempotently.
$rootFolder = Craft::$app->getAssets()->getRootFolderByVolumeId($vol->id);
echo "[pcb_setup] root folder id=" . ($rootFolder ? $rootFolder->id : 'MISSING') . "\n";

// ---- 3. GraphQL schema + bearer token exposing the asset-upload mutation ----
// The `save_<volume>_Asset` mutation is exposed only when the active schema's scope contains
// BOTH `volumes.<uid>:edit` (GqlHelper::canMutateAssets global switch) AND
// `volumes.<uid>:save`/`:create` (per-volume gate). It also needs `sites.<uid>:read`.
use craft\models\GqlSchema;
use craft\models\GqlToken;

$gql = Craft::$app->getGql();
$uid = $vol->uid;
$siteUid = Craft::$app->getSites()->getPrimarySite()->uid;
$wantScope = [
    "volumes.$uid:read",
    "volumes.$uid:edit",
    "volumes.$uid:save",
    "volumes.$uid:create",
    "sites.$siteUid:read",
];

$schema = null;
foreach ($gql->getSchemas() as $s) {
    if ($s->name === 'PCB API') {
        $schema = $s;
        break;
    }
}
if (!$schema) {
    $schema = new GqlSchema();
    $schema->name = 'PCB API';
}
$schema->scope = $wantScope;
if (!$gql->saveSchema($schema)) {
    fail('schema: ' . json_encode($schema->getErrors()));
}

$accessToken = getenv('PCB_GQL_TOKEN') ?: 'pcb_gql_token_ssrf_toctou_0001';
$token = null;
foreach ($gql->getTokens() as $t) {
    if ($t->name === 'PCB Token') {
        $token = $t;
        break;
    }
}
if (!$token) {
    $token = new GqlToken();
    $token->name = 'PCB Token';
}
$token->accessToken = $accessToken;
$token->enabled = true;
$token->expiryDate = null;
$token->schemaId = $schema->id;
if (!$gql->saveToken($token)) {
    fail('token: ' . json_encode($token->getErrors()));
}

// Rebuild the cached GraphQL schema definition so the new scope takes effect immediately.
$gql->invalidateCaches();

// CRITICAL: filesystems (and other project-config components) are written to project config,
// which Craft normally flushes at the END of a request. This script bootstraps Craft without
// running the full request lifecycle, so we must commit the deferred project-config changes
// explicitly — otherwise the `pcbfs` filesystem is lost and the volume resolves to MissingFs.
Craft::$app->getProjectConfig()->saveModifiedConfigData();

echo "[pcb_setup] OK volume=pcbvol uid=$uid schema='PCB API' token='$accessToken' scope=" . json_encode($schema->scope) . "\n";
