<?php

namespace Onixcat\Bundle\SecurityBundle;

use Onixcat\Bundle\SecurityBundle\DependencyInjection\Compiler\AclSchemaResolverPass;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class OnixcatSecurityBundle extends Bundle
{
    /**
     * {@inheritdoc}
     */
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $container->addCompilerPass(new AclSchemaResolverPass);
    }
}
