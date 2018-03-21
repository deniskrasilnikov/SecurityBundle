<?php

namespace Onixcat\Bundle\SecurityBundle\Entity;

class Role
{
    /**
     * @var int
     */
    protected $id;

    /**
     * @var string
     */
    protected $role;

    /**
     * @var \DateTime
     */
    protected $createdAt;

    /**
     * @return int
     */
    public function getId(): int
    {
        return $this->id;
    }

    /**
     * @return \DateTime
     */
    public function getCreatedAt(): \DateTime
    {
        return $this->createdAt;
    }

    /**
     * @param \DateTime $createdAt
     *
     * @return Role
     */
    public function setCreatedAt(\DateTime $createdAt): Role
    {
        $this->createdAt = $createdAt;

        return $this;
    }

    /**
     * @return string
     */
    public function getRole(): string
    {
        return $this->role;
    }

    /**
     * @param string $role
     *
     * @return Role
     */
    public function setRole(string $role): Role
    {
        $this->role = $role;

        return $this;
    }
}
