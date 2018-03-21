<?php

namespace Onixcat\Bundle\SecurityBundle\DependencyInjection\Compiler;

use Onixcat\Bundle\SecurityBundle\Security\Acl\ORM\Schema;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

/**
 * @author Egor Denisenko <e.denisenko@onixcat.com>
 */
class AclSchemaResolverPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container)
    {
        $container->setAlias('security.acl.dbal.connection', 'doctrine.dbal.default_connection');

        if ($container->hasDefinition('security.acl.dbal.schema')) {
            $aclSchemaDefinition = $container->getDefinition('security.acl.dbal.schema');
            $aclSchemaDefinition->setClass(Schema::class);
        } else {
            $container->setDefinition(
                'security.acl.dbal.schema',
                $aclSchemaDefinition = new Definition(Schema::class, [$container->findDefinition('security.acl.dbal.connection')])
            );
        }
        $aclSchemaDefinition->addMethodCall('initialize', []);
    }
}
