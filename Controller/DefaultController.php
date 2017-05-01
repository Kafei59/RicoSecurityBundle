<?php

namespace Rico\SecurityBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;

class DefaultController extends Controller
{
    use ControllerTrait;

    /**
     * DefaultController to test Security ControllerTrait
     *
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function indexAction()
    {
        $this->denyAccessUnlessGranted(array('IS_AUTHENTICATED_ANONYMOUSLY'));

        return $this->render('RicoSecurityBundle:Default:index.html.twig');
    }
}
