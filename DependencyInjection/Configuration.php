<?php
/**
 * This file is part of the SecurityBundle package.
 * (c) Pierrick Gicquelais <pierrick.gicquelais@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * File that was distributed with this source code.
 *
 */

namespace Rico\SecurityBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;


/**
 * Class Configuration
 * @package Rico\SecurityBundle\DependencyInjection
 */
class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('rico_security');

        // Here you should define the parameters that are allowed to
        // configure your bundle. See the documentation linked above for
        // more information on that topic.

        return $treeBuilder;
    }
}
