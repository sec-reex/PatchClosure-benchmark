<?php
/**
 * PCB Probe Plugin for Grav CMS.
 *
 * A thin HTTP endpoint that accepts a Twig payload via POST and processes it
 * through Grav's REAL Twig::processString() pipeline. In Grav 1.7.45+, this
 * method calls Security::cleanDangerousTwig() on the input BEFORE rendering,
 * so the REAL per-version regex sanitiser runs. No source code is lifted --
 * the cleanDangerousTwig method called is the one installed with Grav at the
 * tag this image was built from.
 *
 * Route: GET  /pcb-probe  -> health/ready check
 *        POST /pcb-probe  {"payload":"<twig>"} -> {output, error, pcb_ver}
 */
namespace Grav\Plugin;

use Grav\Common\Plugin;

class PcbProbePlugin extends Plugin
{
    public static function getSubscribedEvents(): array
    {
        return [
            'onPagesInitialized' => ['onPagesInitialized', 0],
        ];
    }

    public function onPagesInitialized(): void
    {
        $uri = $this->grav['uri'];
        if ($uri->path() !== '/pcb-probe') {
            return;
        }

        $pcbVer = getenv('PCB_VER') ?: 'unknown';

        // GET = health check
        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            header('Content-Type: application/json');
            echo json_encode([
                'ok'      => true,
                'pcb_ver' => $pcbVer,
                'usage'   => 'POST /pcb-probe {"payload": "<twig source>"}',
            ]);
            exit;
        }

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'method not allowed']);
            exit;
        }

        $raw  = file_get_contents('php://input');
        $data = json_decode($raw ?: '{}', true);
        $payload = is_array($data) && isset($data['payload']) ? (string) $data['payload'] : '';

        if ($payload === '') {
            http_response_code(400);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'missing "payload"']);
            exit;
        }

        // Ensure Twig is fully initialised (extensions loaded, globals set)
        $twig = $this->grav['twig'];
        $twig->init();

        $output = null;
        $error  = null;
        try {
            // processString() calls Security::cleanDangerousTwig($payload) (V1+)
            // then renders via the real Twig engine with all Grav extensions
            // (including evaluate_twig / evaluate from GravExtension).
            $output = $twig->processString($payload);
        } catch (\Throwable $e) {
            $error = get_class($e) . ': ' . $e->getMessage();
        }

        header('Content-Type: application/json');
        echo json_encode([
            'output'  => $output,
            'error'   => $error,
            'pcb_ver' => $pcbVer,
        ]);
        exit;
    }
}
