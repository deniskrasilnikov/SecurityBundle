<?php

namespace Onixcat\Bundle\SecurityBundle\Security\Acl\Resource\Loader;

use Symfony\Component\Config\Loader\FileLoader;
use Symfony\Component\Yaml\Parser as YamlParser;

class YamlFileLoader extends FileLoader
{
    /**
     * @var YamlParser
     */
    protected $parser = null;

    /**
     * List of all processed view configuration resource files
     *
     * @var array
     */
    protected $resources = [];

    /**
     * {@inheritdoc}
     */
    public function load($file, $type = null): array
    {
        $path = $this->locator->locate($file);

        if (!stream_is_local($path)) {
            throw new \InvalidArgumentException(sprintf('This is not a local file "%s".', $path));
        }

        if (!file_exists($path)) {
            throw new \InvalidArgumentException(sprintf('File "%s" not found.', $path));
        }

        $this->parser = $this->parser ?? new YamlParser;

        if (!$config = $this->parser->parse(file_get_contents($path))) {
            return null;
        }

        if (!is_array($config)) {
            throw new \InvalidArgumentException(sprintf('The file "%s" must contain a YAML array.', $path));
        }

        $fullConfig = [];

        foreach ($config as $name => $value) {
            if (isset($value['resources']) && isset($value['resources']['resource'])) {
                $value['resources'] = $this->import($value['resources']['resource']);
            }

            $fullConfig[$name] = $value;
        }

        return $fullConfig;
    }

    /**
     * {@inheritdoc}
     */
    public function supports($resource, $type = null): bool
    {
        return is_string($resource) && 'yml' === pathinfo($resource, PATHINFO_EXTENSION);
    }
}
