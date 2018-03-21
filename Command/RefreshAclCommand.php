<?php

namespace Onixcat\Bundle\SecurityBundle\Command;

use Onixcat\Bundle\SecurityBundle\Entity\ObjectIdentity;
use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Exception\AclNotFoundException;
use Symfony\Component\Security\Acl\Model\EntryInterface;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;

class RefreshAclCommand extends ContainerAwareCommand
{
    const ROLE_PREFIX = 'ROLE_';

    /**
     * {@inheritdoc}
     */
    protected function configure(): void
    {
        $this->setName('onixcat:acl:refresh')
            ->setDescription('Create and refresh ACL entries');
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output): void
    {
        $container = $this->getContainer();

        $output->writeln('Refreshing ACL entries...');

        $aclProvider = $container->get('onixcat_security.acl_provider');

        $resourceProvider = $container->get('security.resource_provider');
        $resourceConfig = $resourceProvider->getConfig();

        //accumulate all found ids for exclude it from remove query.
        $identityIds = [];

        /** @var ObjectIdentity $resource */
        foreach ($resourceProvider->getCollection() as $resource) {
            try {
                $identity = $aclProvider->findAcl($resource);
            } catch (AclNotFoundException $exception) {
                $identity = $aclProvider->createAcl($resource);
            }

            $identityIds[] = $identity->getId();

            $maskBuilder = new MaskBuilder;
            $foundAceIds = [];

            foreach ($resourceConfig[$resource->getName()]['access'] as $role => $actions) {
                $roleSecurityIdentity = new RoleSecurityIdentity(self::ROLE_PREFIX.strtoupper($role));

                $maskBuilder->reset();

                foreach ($actions as $action) {
                    $maskBuilder->add($action);
                }

                list ($index, $ace) = $this->findAce($identity->getClassAces(), $roleSecurityIdentity);

                // Do update if found but musk is different. Do insert if not found.
                if (null !== $ace) {
                    $foundAceIds[$ace->getId()] = $ace->getId();
                    if ($ace->getMask() !== $maskBuilder->get()) {
                        $identity->updateClassAce($index, $maskBuilder->get());
                    }
                } else {
                    $identity->insertClassAce($roleSecurityIdentity, $maskBuilder->get());
                }
            }

            //remove aces which exist in database but was removed from configurations.
            /** @var EntryInterface $classAce */
            foreach ($identity->getClassAces() as $index => $classAce) {
                if ($classAce->getId() !== null && !isset($foundAceIds[$classAce->getId()])) {
                    $identity->deleteClassAce($index);
                }
            }

            $aclProvider->updateAcl($identity);
        }

        $aclProvider->removeObjectIdentities($identityIds);

        $output->writeln('ACL entries have been refreshed.');
    }

    /**
     * @param array $aces
     * @param RoleSecurityIdentity $roleSecurityIdentity
     *
     * @return array
     */
    private function findAce(array $aces, RoleSecurityIdentity $roleSecurityIdentity): array
    {
        /** @var EntryInterface $ace */
        foreach ($aces as $index => $ace) {
            if ($ace->getSecurityIdentity()->equals($roleSecurityIdentity)) {
                return [$index, $ace];
            }
        }

        return [null, null];
    }
}
