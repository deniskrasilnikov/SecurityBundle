<?php

namespace Onixcat\Bundle\SecurityBundle\Entity;

use Doctrine\Common\Collections\ {
    ArrayCollection, Collection
};
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;

class ObjectIdentity implements ObjectIdentityInterface
{
    const RESOURCE_TYPE_SIMPLE = 'simple',
        RESOURCE_TYPE_ROUTE = 'route',
        RESOURCE_TYPE_CLASS = 'class',
        AVAILABLE_RESOURCE_TYPES = [self::RESOURCE_TYPE_SIMPLE, self::RESOURCE_TYPE_ROUTE, self::RESOURCE_TYPE_CLASS];

    /**
     * @var int
     */
    protected $id;

    /**
     * @var string
     */
    protected $identifier;

    /**
     * @var string
     */
    protected $type;

    /**
     * @var bool
     */
    protected $entriesInheriting;

    /**
     * @var string
     */
    protected $name;

    /**
     * @var Collection
     */
    protected $entries;

    public function __construct()
    {
        $this->entries = new ArrayCollection;
    }

    /**
     * @return int
     */
    public function getId(): int
    {
        return $this->id;
    }

    /**
     * @return string
     */
    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * @param string $identifier
     *
     * @return ObjectIdentity
     */
    public function setIdentifier(string $identifier): ObjectIdentity
    {
        $identifier = trim(strtolower($identifier));

        if ($identifier && !in_array($identifier, self::AVAILABLE_RESOURCE_TYPES)) {
            throw new \InvalidArgumentException("Unknown resource identifier: $identifier");
        }
        $this->identifier = $identifier;

        return $this;
    }

    /**
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @param string $type
     *
     * @return ObjectIdentity
     */
    public function setType(string $type): ObjectIdentity
    {
        $this->type = $type;

        return $this;
    }

    /**
     * @return bool
     */
    public function isEntriesInheriting(): bool
    {
        return $this->entriesInheriting;
    }

    /**
     * @param bool $entriesInheriting
     *
     * @return ObjectIdentity
     */
    public function setEntriesInheriting(bool $entriesInheriting): ObjectIdentity
    {
        $this->entriesInheriting = $entriesInheriting;

        return $this;
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * @param string $name
     *
     * @return ObjectIdentity
     */
    public function setName(string $name): ObjectIdentity
    {
        $this->name = $name;

        return $this;
    }

    /**
     * @return Collection
     */
    public function getEntries(): Collection
    {
        return $this->entries;
    }

    /**
     * @param Entry $entry
     *
     * @return ObjectIdentity
     */
    public function addEntry(Entry $entry): ObjectIdentity
    {
        if (!$this->entries->contains($entry)) {
            $this->entries->add($entry);
        }

        return $this;
    }

    /**
     * @param Entry $entry
     *
     * @return ObjectIdentity
     */
    public function removeEntry(Entry $entry): ObjectIdentity
    {
        $this->entries->removeElement($entry);

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function equals(ObjectIdentityInterface $identity): void
    {
        throw new \RuntimeException('Not implemented yet');
    }
}
