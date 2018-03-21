<?php

namespace Onixcat\Bundle\SecurityBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('onixcat_security');

        $this->addAclSection($rootNode);

        return $treeBuilder;
    }

    private function addAclSection(ArrayNodeDefinition $rootNode)
    {
        $rootNode
            ->children()
                ->arrayNode('acl')
                    ->info('acl resources configuration')
                    ->isRequired()
                    ->cannotBeEmpty()
                    ->children()
                        ->scalarNode('resource')->isRequired()->end()
                    ->end()
                    ->children()
                        ->scalarNode('pattern')->end()
                    ->end()
                ->end()
            ->end();
    }
}
