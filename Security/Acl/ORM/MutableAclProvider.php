<?php

namespace Onixcat\Bundle\SecurityBundle\Security\Acl\ORM;

use Doctrine\Common\PropertyChangedListener;
use Doctrine\ORM\EntityManager;
use Onixcat\Bundle\SecurityBundle\Entity\ObjectIdentity;
use Onixcat\Bundle\SecurityBundle\Entity\Role;
use Symfony\Component\Security\Acl\Domain\Entry;
use Onixcat\Bundle\SecurityBundle\Entity\Entry as OnixcatEntry;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Exception\AclAlreadyExistsException;
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\EntryInterface;
use Symfony\Component\Security\Acl\Model\MutableAclInterface;
use Symfony\Component\Security\Acl\Model\MutableAclProviderInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface as BaseObjectIdentityInterface;
use Symfony\Component\Security\Acl\Model\PermissionGrantingStrategyInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

class MutableAclProvider extends AclProvider implements MutableAclProviderInterface, PropertyChangedListener
{
    /**
     * @var \SplObjectStorage
     */
    protected $propertyChanges;

    /**
     * {@inheritDoc}
     */
    public function __construct(
        EntityManager $entityManager,
        PermissionGrantingStrategyInterface $permissionGrantingStrategy
    ) {
        parent::__construct($entityManager, $permissionGrantingStrategy);

        $this->propertyChanges = new \SplObjectStorage;
    }

    /**
     * {@inheritDoc}
     */
    public function createAcl(BaseObjectIdentityInterface $oid): AclInterface
    {
        if ($this->objectIdentityRepository->merge([$oid])) {
            throw new AclAlreadyExistsException(sprintf('%s is already associated with an ACL.', $oid));
        }
        if ($oid instanceof ObjectIdentity) {
            $oid->setEntriesInheriting(true);
        }
        $this->objectIdentityRepository->saveObjectIdentity($oid);

        return $this->findAcl($oid);
    }

    /**
     * {@inheritDoc}
     */
    public function updateAcl(MutableAclInterface $acl): void
    {
        if (!$this->propertyChanges->contains($acl)) {
            throw new \InvalidArgumentException('$acl is not tracked by this provider.');
        }

        if (!$propertyChanges = $this->propertyChanges->offsetGet($acl)) {
            return;
        }

        if (isset($propertyChanges['aces'])) {
            $this->updateAceProperties($propertyChanges['aces']);
        }

        if (isset($propertyChanges['classAces'])) {
            $this->updateAces($propertyChanges['classAces']);
        }

        $this->propertyChanges->offsetSet($acl, []);
    }

    /**
     * {@inheritDoc}
     */
    public function findAcls(array $oids, array $sids = []): \SplObjectStorage
    {
        $result = parent::findAcls($oids, $sids);

        //Add own listeners on property changed of acl object.
        foreach ($result as $oid) {
            $acl = $result->offsetGet($oid);

            if (false === $this->propertyChanges->contains($acl) && $acl instanceof MutableAclInterface) {
                $acl->addPropertyChangedListener($this);
                $this->propertyChanges->attach($acl, []);
            }
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function propertyChanged($sender, $propertyName, $oldValue, $newValue): void
    {
        if (!$sender instanceof MutableAclInterface && !$sender instanceof EntryInterface) {
            throw new \InvalidArgumentException(
                '$sender must be an instance of MutableAclInterface, or EntryInterface.'
            );
        }
        $ace = null;

        if ($sender instanceof EntryInterface) {
            if (null === $sender->getId()) {
                return;
            }

            $ace = $sender;
            $sender = $ace->getAcl();

        }

        if (false === $this->propertyChanges->contains($sender)) {
            throw new \InvalidArgumentException('$sender is not being tracked by this provider.');
        }

        $propertyChanges = $this->propertyChanges->offsetGet($sender);

        if (null === $ace) {
            if (isset($propertyChanges[$propertyName])) {
                $oldValue = $propertyChanges[$propertyName][0];

                if ($oldValue === $newValue) {
                    unset($propertyChanges[$propertyName]);

                } else {
                    $propertyChanges[$propertyName] = [$oldValue, $newValue];
                }

            } else {
                $propertyChanges[$propertyName] = [$oldValue, $newValue];
            }
        } else {
            if (!isset($propertyChanges['aces'])) {
                $propertyChanges['aces'] = new \SplObjectStorage;
            }

            $acePropertyChanges = $propertyChanges['aces']->contains($ace) ? $propertyChanges['aces']->offsetGet($ace) : [];

            if (isset($acePropertyChanges[$propertyName])) {
                $oldValue = $acePropertyChanges[$propertyName][0];

                if ($oldValue === $newValue) {
                    unset($acePropertyChanges[$propertyName]);
                } else {
                    $acePropertyChanges[$propertyName] = [$oldValue, $newValue];
                }

            } else {
                $acePropertyChanges[$propertyName] = [$oldValue, $newValue];
            }

            if (count($acePropertyChanges) > 0) {
                $propertyChanges['aces']->offsetSet($ace, $acePropertyChanges);

            } else {
                $propertyChanges['aces']->offsetUnset($ace);

                if (0 === count($propertyChanges['aces'])) {
                    unset($propertyChanges['aces']);
                }
            }
        }

        $this->propertyChanges->offsetSet($sender, $propertyChanges);
    }

    /**
     * {@inheritdoc}
     */
    public function deleteAcl(BaseObjectIdentityInterface $oid): void
    {
        throw new \RuntimeException('Not implemented yet');
    }

    /**
     * @param array $excludeIds
     */
    public function removeObjectIdentities(array $excludeIds): void
    {
        $this->objectIdentityRepository->removeObjectIdentities($excludeIds);
    }

    /**
     * @param array $changes
     */
    protected function updateAces(array $changes): void
    {
        list($old, $new) = $changes;

        $currentIds = [];

        foreach ($new as $i => $ace) {
            if ($ace instanceof Entry) {
                /** @var ObjectIdentity $oid */
                $oid = $ace->getAcl()->getObjectIdentity();
                $entry = (new OnixcatEntry)
                    ->setRole($this->extractRole($ace->getSecurityIdentity()))
                    ->setMask($ace->getMask())
                    ->setClass($oid->getType())
                    ->setObjectIdentity($oid)
                    ->setAceOrder($i)
                    ->setGrantingStrategy($ace->getStrategy())
                    ->setGranting($ace->isGranting())
                    ->setAuditSuccess($ace->isAuditSuccess())
                    ->setAuditFailure($ace->isAuditFailure());
                $oid->addEntry($entry);

                $this->entityManager->persist($entry);
            } elseif ($ace instanceof OnixcatEntry && $ace->getId()) {
                $currentIds[$ace->getId()] = $ace->getId();
            }
        }

        /** @var OnixcatEntry $ace */
        foreach ($old as $ace) {
            if (!isset($currentIds[$ace->getId()])) {
                /** @var ObjectIdentity $acl */
                $oid = $ace->getAcl()->getObjectIdentity();
                $oid->removeEntry($ace);
                $this->entityManager->remove($ace);
            }
        }

        $this->entityManager->flush();
    }

    /**
     * @param SecurityIdentityInterface $securityIdentity
     *
     * @return Role
     */
    protected function extractRole(SecurityIdentityInterface $securityIdentity): Role
    {
        if (!$securityIdentity instanceof RoleSecurityIdentity) {
            throw new \InvalidArgumentException("Security identity should be instance of RoleSecurityIdentity, other type not supported.");
        }

        if (!$roles = $this->entityManager->getRepository(Role::class)->findBy(['role' => $securityIdentity->getRole()])) {
            throw new \InvalidArgumentException(sprintf("Role %s does not exist.", $securityIdentity->getRole()));
        }

        return array_shift($roles);
    }

    /**
     * @param \SplObjectStorage $aces
     *
     * @return void
     */
    protected function updateAceProperties(\SplObjectStorage $aces): void
    {
        /** @var  $ace */
        foreach ($aces as $ace) {
            $propertyChanges = $aces->offsetGet($ace);

            foreach ($propertyChanges as $key => $value) {
                $newValue = is_array($value) ? $value[1] : $value;

                if (method_exists($ace, $methodName = $this->getSetterName($key))) {
                    $ace->{$methodName}($newValue);
                }
            }
        }

        $this->entityManager->flush();
    }

    /**
     * @param string $field
     *
     * @return string
     */
    private function getSetterName(string $field): string
    {
        return 'set'.ucfirst(trim($field));
    }
}
