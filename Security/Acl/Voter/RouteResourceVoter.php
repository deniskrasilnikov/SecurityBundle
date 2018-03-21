<?php

namespace Onixcat\Bundle\SecurityBundle\Security\Acl\Voter;

use Onixcat\Bundle\SecurityBundle\Entity\ObjectIdentity;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Acl\Exception\Exception;
use Symfony\Component\Security\Acl\Model\{
    AclProviderInterface, SecurityIdentityRetrievalStrategyInterface
};
use Symfony\Component\Security\Acl\Permission\{
    BasicPermissionMap, PermissionMapInterface
};
use Symfony\Component\Security\Core\Authentication\Token\{
    AnonymousToken, TokenInterface
};
use Symfony\Component\Security\Core\Authorization\Voter\{
    AuthenticatedVoter, VoterInterface
};

class RouteResourceVoter implements VoterInterface
{
    /**
     * @var AclProviderInterface
     */
    protected $aclProvider;

    /**
     * @var PermissionMapInterface
     */
    protected $permissionMap;

    /**
     * @var SecurityIdentityRetrievalStrategyInterface
     */
    protected $securityIdentityRetrievalStrategy;

    /**
     * @var string $aclRoutePattern
     */
    protected $aclRoutePattern;

    /**
     * RouteResourceVoter constructor.
     *
     * @param AclProviderInterface $aclProvider
     * @param SecurityIdentityRetrievalStrategyInterface $sidRetrievalStrategy
     * @param PermissionMapInterface $permissionMap
     * @param string|null $aclRoutePattern
     */
    public function __construct(
        AclProviderInterface $aclProvider,
        SecurityIdentityRetrievalStrategyInterface $sidRetrievalStrategy,
        PermissionMapInterface $permissionMap,
        string $aclRoutePattern = null
    ) {
        $this->aclProvider = $aclProvider;
        $this->permissionMap = $permissionMap;
        $this->securityIdentityRetrievalStrategy = $sidRetrievalStrategy;
        $this->aclRoutePattern = $aclRoutePattern;
    }

    /**
     * @param string $attribute
     *
     * @return bool
     */
    public function supportsAttribute(string $attribute): bool
    {
        return $attribute !== AuthenticatedVoter::IS_AUTHENTICATED_ANONYMOUSLY;
    }

    /**
     * @param $class
     *
     * @return bool
     */
    public function supportsClass($class): bool
    {
        return Request::class == $class || is_subclass_of($class, Request::class);
    }

    /**
     * @param array $attributes
     *
     * @return bool
     */
    protected function supportsAllAttributes(array $attributes): bool
    {
        foreach ($attributes as $attribute) {
            if ($this->supportsAttribute($attribute)) {
                return true;
            }
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function vote(TokenInterface $token, $object, array $attributes): int
    {
        if ($this->aclRoutePattern) {
            if ($object instanceof Request && !preg_match('#'.$this->aclRoutePattern.'#', $object->getPathInfo())) {
                return self::ACCESS_ABSTAIN;
            }
        }

        /** @var Request $object */
        if ($this->supportsClass(get_class($object)) && $this->supportsAllAttributes($attributes)) {
            if ($token instanceof AnonymousToken) {
                return self::ACCESS_DENIED;
            }

            $resource = (new ObjectIdentity)
                ->setIdentifier('route')
                ->setType($object->attributes->get('_route'));

            if ($masks = $this->permissionMap->getMasks(BasicPermissionMap::PERMISSION_VIEW, $resource)) {
                $securityIdentities = $this->securityIdentityRetrievalStrategy->getSecurityIdentities($token);

                try {
                    $acl = $this->aclProvider->findAcl($resource, $securityIdentities);

                    return $acl->isGranted($masks, $securityIdentities, false)
                        ? self::ACCESS_GRANTED
                        : self::ACCESS_DENIED;

                } catch (Exception $exception) {
                    return self::ACCESS_DENIED;
                }
            }
        }

        return self::ACCESS_ABSTAIN;
    }
}
