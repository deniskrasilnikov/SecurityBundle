<?php

namespace Onixcat\Bundle\SecurityBundle\Security\Acl\Resource;

use Onixcat\Bundle\SecurityBundle\Entity\ObjectIdentity;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Config\Loader\LoaderInterface;

class ResourceProvider
{
    /**
     * @var LoaderInterface
     */
    protected $loader;

    /**
     * @var string
     */
    protected $resource;

    /**
     * @var ConfigurationInterface
     */
    protected $configuration;

    /**
     * @var array
     */
    protected $collection = [];

    /**
     * @var array
     */
    protected $config = [];

    /**
     * ResourceProvider constructor.
     * @param LoaderInterface $loader
     * @param string $resource
     * @param ConfigurationInterface $configuration
     */
    public function __construct(LoaderInterface $loader, $resource, ConfigurationInterface $configuration)
    {
        $this->loader = $loader;
        $this->resource = $resource;
        $this->configuration = $configuration;
    }

    /**
     * @return array
     */
    public function getCollection(): array
    {
        foreach ($this->getConfig() as $resource) {
            $this->collection[] =
                (new ObjectIdentity)
                    ->setIdentifier($resource['type'])
                    ->setType($resource['target'])
                    ->setName($resource['name']);
        }

        return $this->collection;
    }

    /**
     * @return array
     */
    public function getConfig(): array
    {
        if ($this->config) {
            return $this->config;
        }

        foreach ((new Processor)->processConfiguration($this->configuration, [$this->loader->load($this->resource)]) as $groupName => $group) {
            if ($group['resources']) {
                $this->parseResource($this->config, $groupName, $group);
            }
        }

        return $this->config;
    }

    /**
     * @param array $result
     * @param string $groupName
     * @param array $group
     */
    private function parseResource(array &$result, string $groupName, array $group): void
    {
        foreach ($group['resources'] as $resourceName => $resource) {
            $name = $groupName.'.'.$resourceName;

            $resource['name'] = $name;
            $resource['title'] = $group['title'] ? $group['title'].' | '.$resource['title'] : $resource['title'];

            $result[$name] = $resource;
        }
    }
}
