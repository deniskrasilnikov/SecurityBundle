<?php

namespace Onixcat\Bundle\SecurityBundle\Security\Acl\ORM;

use Doctrine\DBAL\Schema\Schema as BaseSchema;
use Doctrine\DBAL\Connection;

/**
 * The schema used for the ACL system.
 *
 * @author Egor Denisenko <e.denisenko@onixcat.com>
 */
final class Schema extends BaseSchema
{
    const ENTRY_TABLE_NAME = 'onixcat_acl_entry',
        OID_TABLE_NAME = 'onixcat_acl_object_identity',
        ROLE_TABLE_NAME = 'onixcat_user_role';

    /**
     * Schema constructor.
     * @param Connection|null $connection
     */
    public function __construct(Connection $connection)
    {
        parent::__construct([], [], $connection->getSchemaManager()->createSchemaConfig());
    }

    /**
     * Create acl tables.
     */
    public function initialize(): void
    {
        $this->addRoleTable();
        $this->addObjectIdentitiesTable();
        $this->addEntryTable();
    }

    /**
     * Merges ACL schema with the given schema.
     *
     * @param BaseSchema $schema
     */
    public function addToSchema(BaseSchema $schema): void
    {
        foreach ($this->getTables() as $table) {
            $schema->_addTable($table);
        }

        foreach ($this->getSequences() as $sequence) {
            $schema->_addSequence($sequence);
        }
    }

    /**
     * Adds the role table to the schema.
     */
    protected function addRoleTable(): void
    {
        $table = $this->createTable(self::ROLE_TABLE_NAME);

        $table->addColumn('id', 'integer', ['unsigned' => true, 'autoincrement' => 'auto']);
        $table->addColumn('role', 'string');
        $table->addColumn('created_at', 'datetime');

        $table->setPrimaryKey(['id']);
        $table->addUniqueIndex(['role']);
    }

    /**
     * Adds the entry table to the schema.
     */
    protected function addEntryTable(): void
    {
        $table = $this->createTable(self::ENTRY_TABLE_NAME);

        $table->addColumn('id', 'integer', ['unsigned' => true, 'autoincrement' => 'auto']);
        $table->addColumn('object_identity_id', 'integer', ['unsigned' => true, 'notnull' => false]);
        $table->addColumn('role_id', 'integer', ['unsigned' => true, 'notnull' => false]);
        $table->addColumn('aceOrder', 'integer');
        $table->addColumn('mask', 'integer');
        $table->addColumn('granting', 'boolean');
        $table->addColumn('grantingStrategy', 'string');
        $table->addColumn('auditSuccess', 'boolean');
        $table->addColumn('auditFailure', 'boolean');
        $table->addColumn('class', 'string');

        $table->setPrimaryKey(['id']);
        $table->addIndex(['object_identity_id']);
        $table->addIndex(['role_id']);
        $table->addForeignKeyConstraint(
            $this->getTable(self::OID_TABLE_NAME),
            ['object_identity_id'],
            ['id'],
            ['onDelete' => 'RESTRICT', 'onUpdate' => 'RESTRICT']
        );
        $table->addForeignKeyConstraint(
            $this->getTable(self::ROLE_TABLE_NAME),
            ['role_id'],
            ['id'],
            ['onDelete' => 'RESTRICT', 'onUpdate' => 'RESTRICT']
        );

    }

    /**
     * Adds the object identity table to the schema.
     */
    protected function addObjectIdentitiesTable(): void
    {
        $table = $this->createTable(self::OID_TABLE_NAME);

        $table->addColumn('id', 'integer', ['unsigned' => true, 'autoincrement' => 'auto']);
        $table->addColumn('identifier', 'string');
        $table->addColumn('type', 'string');
        $table->addColumn('entriesInheriting', 'boolean');
        $table->addColumn('name', 'string');

        $table->setPrimaryKey(['id']);
        $table->addUniqueIndex(['name']);
    }
}
