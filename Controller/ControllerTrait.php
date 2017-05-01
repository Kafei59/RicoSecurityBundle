<?php
/**
 * This file is part of the SecurityBundle package.
 * (c) Pierrick Gicquelais <pierrick.gicquelais@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * File that was distributed with this source code.
 *
 */

namespace Rico\SecurityBundle\Controller;


use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\RuntimeException;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Class ControllerTrait
 * @package Rico\SecurityBundle\Controller
 */
trait ControllerTrait
{
    /**
     * Deny access if user is not granted $attributes on $object
     *
     * @param mixed $attributes         The attributes to check
     * @param mixed $subject            The subject to secure, e.g an object the user wants to access
     * @param null $user                The user who wants to access the subject
     * @param string $message           The message when AccessDenied exception throws up
     *
     * @throws AccessDeniedException    When user is not granted attributes on subject
     */
    protected function denyAccessUnlessGranted($attributes, $subject = null, $user = null, $message = "Access Denied.")
    {
        if (!$this->container instanceof ContainerInterface) {
            throw new RuntimeException("Controller must implement ContainerAwareTrait and Interface to enhanced Security.");
        }

        if (!$this->container->has('security.authorization_checker')) {
            throw new \LogicException('The SecurityBundle is not registered in your application.');
        }

        if (!is_array($attributes)) {
            $attributes = array($attributes);
        }

        if (!$this->isGranted($attributes, $subject, $user)) {
            throw new AccessDeniedException($message);
        }
    }

    /**
     * Verify if attributes are granted for subject if defined and for user if defined
     *
     * @param mixed $attributes         The attributes to check
     * @param mixed $subject            The subject to secure, e.g an object the user wants to access
     * @param UserInterface $user       The user who wants to access the subject
     *
     * @return bool                     True if user has attributes on subject
     */
    protected function isGranted($attributes, $subject = null, UserInterface $user = null)
    {
        if ($subject and $user) {
            $token = new UsernamePasswordToken($user, 'none', 'none', $user->getRoles());

            return $this->container->get('security.access.decision_manager')->decide($token, $attributes, $subject);
        } else {
            return $this->container->get('security.authorization_checker')->isGranted($attributes, $subject);
        }
    }


    // TODO: transform it
//    /**
//     * Access Denied if AbstractUser does not have correct permissions on $object
//     * Throws Exception also if LegalEntity not found when Role is Pro
//     *
//     * @param $attributes
//     * @param $object
//     * @param AbstractUser $user
//     * @param LegalEntity|null $legalEntity
//     */
//    protected function denyAccessIfNotGranted($attributes, $object, AbstractUser $user, LegalEntity $legalEntity = null)
//    {
//        if (!is_array($attributes)) {
//            $attributes = array($attributes);
//        }
//
//        if ($this->userIsGranted(Role::PRO, $user)) {
//            if (!$legalEntity instanceof LegalEntity) {
//                throw new NotFoundHttpException('exception.legal_entity.not_found');
//            }
//
//            if (!is_string($object)) {
//                if ($this->isGranted($attributes, $object)) {
//                    return;
//                }
//
//                $this->denyAccessUnlessGranted($attributes, $object, $legalEntity);
//            }
//
//            if ($legalEntity->getOwner() != $user) {
//                $manager = $this->get('pumpkin.core.permission_manager');
//                foreach ($attributes as $mask) {
//                    if (!$manager->hasPermission($mask, $object, $user, $legalEntity)) {
//                        throw new AccessDeniedHttpException('exception.permission.access_denied');
//                    }
//                }
//            }
//        } else {
//            if (!is_string($object)) {
//                $this->denyAccessUnlessGranted($attributes, $object, $user);
//            }
//        }
//    }
}