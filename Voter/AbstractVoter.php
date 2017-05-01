<?php
/**
 * This file is part of the SecurityBundle package.
 * (c) Pierrick Gicquelais <pierrick.gicquelais@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * File that was distributed with this source code.
 *
 */

namespace Rico\SecurityBundle\Voter;


use Symfony\Component\Security\Core\Authorization\Voter\Voter;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Class AbstractVoter
 * @package Rico\SecurityBundle\Voter
 */
abstract class AbstractVoter extends Voter
{
    /**
     * Determines if the attribute and subject are supported by this voter.
     *
     * @param string $attribute An attribute to check
     * @param mixed $subject    The subject to secure, e.g. an object the user wants to access
     *
     * @return bool             True if the attribute and subject are supported, false otherwise
     */
    protected function supports($attribute, $subject)
    {
        if (!$subject->getId()) {
            return VoterInterface::ACCESS_ABSTAIN;
        }

        return true;
    }

    /**
     * Perform a single access check operation on a given attribute, subject and token.
     *
     * @param string $attribute     An attribute to check
     * @param mixed $subject        The subject to secure, e.g an object the user wants to access
     * @param TokenInterface $token The token interface of user who wants to access the subject
     *
     * @return bool                 True if the user has access to the attribute on the subject
     */
    protected function voteOnAttribute($attribute, $subject, TokenInterface $token)
    {
        $user = $token->getUser();

        if (!$user instanceof UserInterface) {
            return VoterInterface::ACCESS_ABSTAIN;
        }

        // TODO: find in subject permissions if user is present and bitwise check attribute
        return true;

//        foreach ($subject->getUserPermissions() as $permissions) {
//            if ($permissions instanceof PermissionInterface) {
//                if ($permissions->getUser() == $user) {
//                    return $this->isGrantedAttribute($permissions->getValues(), $attribute) === VoterInterface::ACCESS_GRANTED;
//                }
//            }
//        }
//
//        return false;
    }

    /**
     * Verify if required $attribute is in given $permissions by performing a bitwise check
     *
     * @param int $permissions  The user permissions on the subject
     * @param int $attribute    An attribute to check
     *
     * @return int              ACCESS_GRANTED if bitwise check returns true otherwise ACCESS_DENIED
     */
    protected function isGrantedAttribute(int $permissions, int $attribute)
    {
        if ($this->hasAttribute($permissions, $attribute)) {
            return VoterInterface::ACCESS_GRANTED;
        } else {
            return VoterInterface::ACCESS_DENIED;
        }
    }

    /**
     * Perform a bitwise check
     *
     * @param int $permissions  The user permissions on the subject
     * @param int $attribute    An attribute to check
     *
     * @return bool             True if bitwise check is true
     */
    protected function hasAttribute(int $permissions, int $attribute)
    {
        return ($permissions & $attribute) === $attribute;
    }
}