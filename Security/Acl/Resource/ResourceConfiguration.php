<?php

namespace Onixcat\Bundle\SecurityBundle\Security\Acl\Resource;

use Onixcat\Bundle\SecurityBundle\Entity\ObjectIdentity;
use Onixcat\Bundle\SecurityBundle\Entity\Repository\RoleRepository;
use Onixcat\Bundle\SecurityBundle\Entity\Role;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\HttpKernel\KernelInterface;

class ResourceConfiguration implements ConfigurationInterface
{
    //@see https://symfony.com/doc/current/security/acl_advanced.html#built-in-permission-map
    const PERMISSIBLE_ACTIONS = ['view', 'create', 'edit', 'delete', 'undelete', 'operator', 'master', 'owner'];

    /**
     * @var RouterInterface
     */
    protected $router;

    /**
     * @var KernelInterface
     */
    protected $kernel;

    /**
     * @var RoleRepository
     */
    protected $roleRepository;

    /**
     * ResourceConfiguration constructor.
     * @param RouterInterface $router
     * @param KernelInterface $kernel
     * @param RoleRepository $roleRepository
     */
    public function __construct(RouterInterface $router, KernelInterface $kernel, RoleRepository $roleRepository)
    {
        $this->router = $router;
        $this->kernel = $kernel;
        $this->roleRepository = $roleRepository;
    }

    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder;

        $rootNode = $treeBuilder->root(null);

        $rootNode
            ->useAttributeAsKey('name')
            ->prototype('array')
                ->children()
                    ->scalarNode('title')
                        ->isRequired()
                        ->cannotBeEmpty()
                    ->end()
                    ->arrayNode('resources')
                        ->useAttributeAsKey('name')
                        ->prototype('array')
                            ->children()
                                ->scalarNode('title')
                                    ->isRequired()
                                    ->cannotBeEmpty()
                                ->end()
                                ->enumNode('type')
                                    ->values(ObjectIdentity::AVAILABLE_RESOURCE_TYPES)
                                    ->defaultValue(ObjectIdentity::RESOURCE_TYPE_SIMPLE)
                                    ->cannotBeEmpty()
                                ->end()
                                ->scalarNode('target')
                                    ->isRequired()
                                    ->cannotBeEmpty()
                                ->end()
                                ->arrayNode('access')
                                    ->defaultValue([])
                                    ->useAttributeAsKey('name')
                                    ->prototype('array')
                                        ->prototype('scalar')->end()
                                    ->end()
                                    ->validate()
                                        ->always(
                                            function ($element) {
                                                $this->validateAccess($element);

                                                return $element;
                                            }
                                        )
                                    ->end()
                                ->end()
                            ->end()
                            ->validate()
                                ->always(
                                    function ($element) {
                                        $element['type'] === ObjectIdentity::RESOURCE_TYPE_CLASS && $this->validateClass($element);
                                        $element['type'] === ObjectIdentity::RESOURCE_TYPE_ROUTE && $this->validateRoute($element);

                                        return $element;
                                    }
                                )
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end()
        ->end();

        return $treeBuilder;
    }

    /**
     * @param array $resource
     */
    protected function validateClass(array $resource): void
    {
        if (!class_exists($resource['target'])) {
            throw new \InvalidArgumentException('Invalid target class: '.$resource['target'].'. Class not exists.');
        }
    }

    /**
     * @param array $resource
     */
    protected function validateRoute(array $resource): void
    {
        if (!in_array($resource['target'], array_keys($this->router->getRouteCollection()->all()))) {
            throw new \InvalidArgumentException('Invalid route name: '.$resource['target'].'. Route not exists.');
        }
    }

    /**
     * @param array $resource
     */
    protected function validateController(array $resource): void
    {
        /** @var \ReflectionClass[] $controllerReflections */
        static $controllerReflections = [];

        if (!preg_match('/(?P<bundle>.+)\:(?P<controller>.+)\:(?P<action>.+)/i', $resource['target'], $matched = [])) {
            throw new \InvalidArgumentException('Invalid target format.');
        }

        $bundle = $this->kernel->getBundle($matched['bundle']);
        $controllerClass = $bundle->getNamespace().'\\Controller\\'.$matched['controller'].'Controller';

        if (!class_exists($controllerClass)) {
            throw new \InvalidArgumentException('Target Controller not exists');
        }

        if (!array_key_exists($controllerClass, $controllerReflections)) {
            $controllerReflections[$controllerClass] = new \ReflectionClass($controllerClass);
        }

        if (!$controllerReflections[$controllerClass]->hasMethod($matched['action'].'Action')) {
            throw new \InvalidArgumentException('Target controller has no action \''.$matched['action'].'\'');
        }
    }

    /**
     * @param array $access
     */
    protected function validateAccess(array $access): void
    {
        /** @var  $allRoles */
        static $allRoles = null;

        if ($allRoles === null) {
            $allRoles = array_map(
                function (Role $role) {
                    return strtolower(preg_replace('/^ROLE_(.+)$/', '$1', $role->getRole()));
                },
                $this->roleRepository->findAll()
            );
        }

        foreach ($access as $role => $actions) {
            if (!in_array(strtolower($role), $allRoles)) {
                throw new \InvalidArgumentException(
                    'The role "'.$role.'" is not allowed. Permissible roles: "'.implode('", "', $allRoles).'"'
                );
            }

            if ($invalidActions = array_diff($actions, self::PERMISSIBLE_ACTIONS)) {
                throw new \InvalidArgumentException(
                    sprintf(
                        'The actions "%s" are not allowed. Permissible actions: "%s"',
                        implode('", "', $invalidActions),
                        implode('", "', self::PERMISSIBLE_ACTIONS)
                    )
                );
            }
        }
    }
}
