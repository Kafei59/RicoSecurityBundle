<?php
/**
 * This file is part of the SecurityBundle package.
 * (c) Pierrick Gicquelais <pierrick.gicquelais@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * File that was distributed with this source code.
 *
 */

namespace Rico\SecurityBundle\MaskBuilder;


use Symfony\Component\Security\Core\Exception\InvalidArgumentException;

/**
 * Class AbstractMaskBuilder
 * @package Rico\SecurityBundle\MaskBuilder
 */
abstract class AbstractMaskBuilder
{
    /** DEFAULT MASKS */
    const MASK_EMPTY = 0;
    const MASK_VIEW = 1;
    const MASK_CREATE = 2;
    const MASK_EDIT = 4;
    const MASK_DELETE = 8;
    const MASK_UNDELETE = 16;
    const MASK_LIST = 32;

    /** OPERATORS MASKS */
    const MASK_OPERATOR = 268435455;
    const MASK_MASTER = 536870911;
    const MASK_OWNER = 1073741823;

    /** @var int */
    protected $mask;

    /**
     * Constructor.
     *
     * @param int $mask optional; defaults to 0
     */
    public function __construct($mask = 0)
    {
        $this->set($mask);
    }

    /**
     * Set mask builder to new value
     *
     * @param int $mask                 The mask value to set
     * @return $this                    The new MaskBuilder value
     * @throws InvalidArgumentException If mask it not an integer
     */
    public function set($mask)
    {
        if (!is_int($mask)) {
            throw new InvalidArgumentException('$mask must be an integer.');
        }

        $this->mask = $mask;

        return $this;
    }

    /**
     * Get mask builder value
     *
     * @return int  The MaskBuilder value
     */
    public function get()
    {
        return $this->mask;
    }

    /**
     * Add a new value to mask builder
     *
     * @param int $mask     The mask value to add
     * @return $this        The new MaskBuilder value
     */
    public function add($mask)
    {
        $this->mask |= $this->resolveMask($mask);

        return $this;
    }

    /**
     * Remove a value from mask builder
     *
     * @param int $mask         The mask value to remove
     * @return $this            The new MaskBuilder value
     */
    public function remove($mask)
    {
        $this->mask &= ~$this->resolveMask($mask);

        return $this;
    }

    /**
     * Reset mask builder to default value, by default 0
     *
     * @return $this            The new MaskBuilder value
     */
    public function reset()
    {
        $this->mask = 0;

        return $this;
    }

    /**
     * Returns the mask for the passed code.
     *
     * @param mixed $code                   The code value of a mask
     * @return int                          The value of a mask
     * @throws InvalidArgumentException     If code is not supported or is not an integer
     */
    public function resolveMask($code)
    {
        if (is_string($code)) {
            if (!defined($name = sprintf('static::MASK_%s', strtoupper($code)))) {
                throw new InvalidArgumentException('$code not supported.');
            }

            return constant($name);
        }

        if (!is_int($code)) {
            throw new InvalidArgumentException('$code must be an integer.');
        }

        return $code;
    }

    /**
     * Return array of all masks
     *
     * @return array
     */
    public static function getMasks()
    {
        return array(
            self::MASK_EMPTY,
            self::MASK_VIEW,
            self::MASK_CREATE,
            self::MASK_EDIT,
            self::MASK_DELETE,
            self::MASK_UNDELETE,
            self::MASK_LIST,

            self::MASK_OPERATOR,
            self::MASK_MASTER,
            self::MASK_OWNER
        );
    }
}