<?php

namespace Onixcat\Bundle\SecurityBundle\Entity;

use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\EntryInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;

class Entry implements EntryInterface
{
    /**
     * @var int
     */
    protected $id;

    /**
     * @var ObjectIdentityInterface
     */
    protected $objectIdentity;

    /**
     * @var int
     */
    protected $aceOrder;

    /**
     * @var Role
     */
    protected $role;

    /**
     * @var int
     */
    protected $mask;

    /**
     * @var bool
     */
    protected $granting;

    /**
     * @var string
     */
    protected $grantingStrategy;

    /**
     * @var bool
     */
    protected $auditSuccess;

    /**
     * @var bool
     */
    protected $auditFailure;

    /**
     * @var string
     */
    protected $class;

    /**
     * @var AclInterface
     */
    protected $acl;

    /**
     * @var RoleSecurityIdentity
     */
    protected $securityIdentity;

    /**
     * @return int
     */
    public function getId(): int
    {
        return $this->id;
    }

    /**
     * @return ObjectIdentityInterface
     */
    public function getObjectIdentity(): ObjectIdentityInterface
    {
        return $this->objectIdentity;
    }

    /**
     * @param ObjectIdentityInterface $objectIdentity
     *
     * @return Entry
     */
    public function setObjectIdentity(ObjectIdentityInterface $objectIdentity): Entry
    {
        $this->objectIdentity = $objectIdentity;

        return $this;
    }

    /**
     * @return int
     */
    public function getAceOrder(): int
    {
        return $this->aceOrder;
    }

    /**
     * @param int $aceOrder
     *
     * @return Entry
     */
    public function setAceOrder(int $aceOrder): Entry
    {
        $this->aceOrder = $aceOrder;

        return $this;
    }

    /**
     * @return Role
     */
    public function getRole(): Role
    {
        return $this->role;
    }

    /**
     * @param Role $role
     *
     * @return Entry
     */
    public function setRole(Role $role): Entry
    {
        $this->role = $role;

        return $this;
    }

    /**
     * @return int
     */
    public function getMask(): int
    {
        return $this->mask;
    }

    /**
     * @param int $mask
     *
     * @return Entry
     */
    public function setMask(int $mask): Entry
    {
        $this->mask = $mask;

        return $this;
    }

    /**
     * @return bool
     */
    public function isGranting(): bool
    {
        return $this->granting;
    }

    /**
     * @param bool $granting
     *
     * @return Entry
     */
    public function setGranting(bool $granting): Entry
    {
        $this->granting = $granting;

        return $this;
    }

    /**
     * @return string
     */
    public function getGrantingStrategy(): string
    {
        return $this->grantingStrategy;
    }

    /**
     * @param string $grantingStrategy
     *
     * @return Entry
     */
    public function setGrantingStrategy(string $grantingStrategy): Entry
    {
        $this->grantingStrategy = $grantingStrategy;

        return $this;
    }

    /**
     * @return bool
     */
    public function isAuditSuccess(): bool
    {
        return $this->auditSuccess;
    }

    /**
     * @param bool $auditSuccess
     *
     * @return Entry
     */
    public function setAuditSuccess(bool $auditSuccess): Entry
    {
        $this->auditSuccess = $auditSuccess;

        return $this;
    }

    /**
     * @return bool
     */
    public function isAuditFailure(): bool
    {
        return $this->auditFailure;
    }

    /**
     * @param bool $auditFailure
     *
     * @return Entry
     */
    public function setAuditFailure(bool $auditFailure): Entry
    {
        $this->auditFailure = $auditFailure;

        return $this;
    }

    /**
     * @return string
     */
    public function getClass(): string
    {
        return $this->class;
    }

    /**
     * @param string $class
     *
     * @return Entry
     */
    public function setClass(string $class): Entry
    {
        $this->class = $class;

        return $this;
    }

    /**
     * @return AclInterface
     */
    public function getAcl(): AclInterface
    {
        return $this->acl;
    }

    /**
     * @param AclInterface $acl
     *
     * @return Entry
     */
    public function setAcl(AclInterface $acl): Entry
    {
        $this->acl = $acl;

        return $this;
    }

    /**
     * @return RoleSecurityIdentity
     */
    public function getSecurityIdentity(): RoleSecurityIdentity
    {
        return $this->securityIdentity;
    }

    /**
     * @param RoleSecurityIdentity $securityIdentity
     *
     * @return Entry
     */
    public function setSecurityIdentity(RoleSecurityIdentity $securityIdentity): Entry
    {
        $this->securityIdentity = $securityIdentity;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function serialize(): ?string
    {
        return serialize(
            array(
                $this->mask,
                $this->id,
                $this->securityIdentity,
                $this->grantingStrategy,
                $this->auditFailure,
                $this->auditSuccess,
                $this->granting,
            )
        );
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize($serialized): void
    {
        list(
            $this->mask,
            $this->id,
            $this->securityIdentity,
            $this->grantingStrategy,
            $this->auditFailure,
            $this->auditSuccess,
            $this->granting
            ) = unserialize($serialized);
    }

    /**
     * The strategy for comparing masks.
     *
     * @return string
     */
    public function getStrategy(): string
    {
        return $this->getGrantingStrategy();
    }
}
