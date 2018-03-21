<?php

namespace Onixcat\Bundle\SecurityBundle\Security\Acl\ORM;

use Doctrine\ORM\EntityManager;
use Onixcat\Bundle\SecurityBundle\Entity\ObjectIdentity;
use Onixcat\Bundle\SecurityBundle\Entity\Repository\ObjectIdentityRepository;
use Symfony\Component\Security\Acl\Domain\Acl;
use Onixcat\Bundle\SecurityBundle\Entity\Entry;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Exception\AclNotFoundException;
use Symfony\Component\Security\Acl\Exception\NotAllAclsFoundException;
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\AclProviderInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface as BaseObjectIdentityInterface;
use Symfony\Component\Security\Acl\Model\PermissionGrantingStrategyInterface;

class AclProvider implements AclProviderInterface
{
    const MAX_BATCH_SIZE = 30;

    /**
     * @var EntityManager
     */
    protected $entityManager;

    /**
     * @var PermissionGrantingStrategyInterface
     */
    protected $permissionGrantingStrategy;

    /**
     * @var ObjectIdentityRepository
     */
    protected $objectIdentityRepository;

    /**
     * AclProvider constructor.
     * @param EntityManager $entityManager
     * @param PermissionGrantingStrategyInterface $permissionGrantingStrategy
     */
    public function __construct(EntityManager $entityManager, PermissionGrantingStrategyInterface $permissionGrantingStrategy)
    {
        $this->entityManager = $entityManager;
        $this->permissionGrantingStrategy = $permissionGrantingStrategy;
        $this->objectIdentityRepository = $this->entityManager->getRepository(ObjectIdentity::class);
    }

    /**
     * {@inheritDoc}
     */
    public function findChildren(BaseObjectIdentityInterface $parentOid, $directChildrenOnly = false): void
    {
        throw new \RuntimeException('Not implemented yet');
    }

    /**
     * {@inheritDoc}
     */
    public function findAcl(BaseObjectIdentityInterface $oid, array $sids = []): AclInterface
    {
        /** @var ObjectIdentity $oid */
        $oid = $this->lookupObjectIdentities([$oid])[0];

        return $this->findAcls([$oid], $sids)->offsetGet($oid);
    }

    /**
     * {@inheritDoc}
     */
    public function findAcls(array $oids, array $sids = []): \SplObjectStorage
    {
        $result = new \SplObjectStorage;
        $currentBatch = [];
        $count = count($oids);
        $oids = $this->lookupObjectIdentities($oids);

        if (count($oids) < $count) {
            if (1 === $count) {
                throw new AclNotFoundException(sprintf('No ACL found for %s.', array_shift($oids)));
            }

            throw new NotAllAclsFoundException('The provider could not find ACLs for all object identities.');
        }

        for ($i = 0; $i < $count; $i++) {
            /** @var ObjectIdentity $oid */
            $oid = $oids[$i];

            if (!$result->contains($oid)) {
                $currentBatch[] = $oid;
            }

            if ($currentBatch && (self::MAX_BATCH_SIZE === count($currentBatch) || ($i + 1) === $count)) {
                $loadedBatch = $this->hydrateObjectIdentities($currentBatch);

                foreach ($loadedBatch as $loadedOid) {
                    $result->attach($loadedOid, $loadedBatch->offsetGet($loadedOid));
                }

                $currentBatch = [];
            }
        }

        return $result;
    }

    /**
     * This method is called for object identities which could not be retrieved
     * from the cache, and for which thus a database query is required.
     *
     * @param array $batch
     *
     * @return array
     */
    protected function lookupObjectIdentities(array $batch): array
    {
        if (!$objIdentities = $this->objectIdentityRepository->merge($batch)) {
            throw new AclNotFoundException('There is no ACL for the given object identity.');
        }

        return $objIdentities;
    }

    /**
     * This method is called to hydrate ACLs and ACEs.
     *
     * @param array $objectIdentities
     *
     * @return \SplObjectStorage
     */
    protected function hydrateObjectIdentities(array $objectIdentities): \SplObjectStorage
    {
        $result = new \SplObjectStorage;

        // we need these to set protected properties on hydrated objects
        $aclReflection = new \ReflectionClass(Acl::class);
        $aclClassAcesProperty = $aclReflection->getProperty('classAces');
        $aclClassAcesProperty->setAccessible(true);

        /** @var ObjectIdentity $objectIdentity */
        foreach ($objectIdentities as $objectIdentity) {

            $acl = new Acl($objectIdentity->getId(), $objectIdentity, $this->permissionGrantingStrategy, [], $objectIdentity->isEntriesInheriting());

            $result->attach($objectIdentity, $acl);

            $ace = [];

            //accumulate aces
            /** @var Entry $entry */
            foreach ($objectIdentity->getEntries() as $entry) {
                $ace[] = $entry
                    ->setAcl($acl)
                    ->setSecurityIdentity(new RoleSecurityIdentity($entry->getRole()->getRole()));
            }

            $aclClassAcesProperty->setValue($acl, $ace);
        }

        $aclClassAcesProperty->setAccessible(false);

        return $result;
    }
}
