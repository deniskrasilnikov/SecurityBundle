<?php

namespace Onixcat\Bundle\SecurityBundle\Entity\Repository;

use Doctrine\ORM\EntityRepository;
use Onixcat\Bundle\SecurityBundle\Entity\ObjectIdentity;
use Onixcat\Bundle\SecurityBundle\Security\Acl\ORM\Schema;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;

class ObjectIdentityRepository extends EntityRepository
{
    /**
     * Retrieve the entity associated with the values in the ObjectIdentity
     *
     * @param array $entities
     *
     * @return array
     */
    public function merge(array $entities): array
    {
        $qb = $this->createQueryBuilder('oi');

        $orX = $qb->expr()->orX();

        /** @var ObjectIdentity $entity */
        foreach ($entities as $key => $entity) {
            $orX->add(
                $qb->expr()->andX()
                    ->add('oi.identifier=:identifier'.$key)
                    ->add('oi.type=:type'.$key)
            );
            $qb->setParameter('identifier'.$key, $entity->getIdentifier())
                ->setParameter('type'.$key, $entity->getType());
        }

        if (!$orX->count()) {
            return [];
        }

        return $qb
            ->addSelect('e')
            ->leftJoin('oi.entries', 'e')
            ->where($orX)
            ->getQuery()
            ->getResult();
    }

    /**
     * Remove all rows exclude given ids.
     *
     * @param array $excludeId
     */
    public function removeObjectIdentities(array $excludeId): void
    {
        if ($excludeId) {
            $this->execDeleteQuery(Schema::ENTRY_TABLE_NAME, sprintf(' WHERE object_identity_id not in (%s)', implode(',', $excludeId)));
            $this->execDeleteQuery(Schema::OID_TABLE_NAME, sprintf(' WHERE id not in (%s)', implode(',', $excludeId)));

            return;
        }

        $this->execDeleteQuery(Schema::ENTRY_TABLE_NAME);
        $this->execDeleteQuery(Schema::OID_TABLE_NAME);
    }

    /**
     * @param ObjectIdentityInterface $oid
     */
    public function saveObjectIdentity(ObjectIdentityInterface $oid): void
    {
        $this->_em->persist($oid);
        $this->_em->flush();
    }

    /**
     * @param string $tableName
     * @param string $whereClause
     */
    private function execDeleteQuery(string $tableName, string $whereClause = ''): void
    {
        $this->_em->getConnection()->executeQuery("delete from $tableName $whereClause");
    }
}
