<?php

namespace Rico\SecurityBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;

class DefaultController extends Controller
{
    public function indexAction()
    {
        return $this->render('RicoSecurityBundle:Default:index.html.twig');
    }
}
