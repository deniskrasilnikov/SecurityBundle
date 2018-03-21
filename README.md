OnixcatSecurityBundle
==============

## Installation

1. Add to **app/AppKernel.php** the next code

        // ...
        public function registerBundles()
        {
            $bundles = array(
                // ...
                new \Doctrine\Bundle\DoctrineBundle\DoctrineBundle(),
                new Onixcat\Bundle\SecurityBundle\OnixcatSecurityBundle(),
                // ...
            );
            // ...
        }
        
2. Change **app/config/security.yml**.
  
        security:
            acl:
                connection: default
                provider: onixcat_security.acl_provider

            access_decision_manager:
                strategy: unanimous # strategy required for proper access restriction to route acl resources

4. Add to **app/config/config.yml**

        ...
        onixcat_security:
            acl:
                resource: "%kernel.root_dir%/config/acl.yml"

5. Add **acl.yml** to *app/config*
        
        acl_group_name:
            title: Group title #should be prepended for each resource in this group
            resources:
                resource_name:
                    title: Resource title
                    
                    # type: Resource type
                    # Permissible values: simple, class, route
                    type: class 
                    
                    # target: 
                    # For each type target should point to:
                    #    simple: Custom identifier, for example: access_to_expired_vouchers
                    #    class: Full class name
                    #    route: Route name
                    target: onixcat_index_page 
                    
                    access:
                        # role: [action1, action2]
                        # Role should be defined in lower case without ROLE_ prefix 
                        # Permissible actions: 'view', 'create', 'edit', 'delete', 'undelete', 'operator', 'master', 'owner'
                        # see https://symfony.com/doc/current/security/acl_advanced.html#built-in-permission-map
                        user: [view, edit]
                        admin: [create]                            
                    
                # Also you can use 'resource' in resources section. 'resource' must points to other acl config
                resource: "@OnixcatSecurityBundle/Resources/config/acl.yml"   
                    
6. Do composer update
 
7. Run commands
       
        > bin/console init:acl
        
        You should create needed roles in onixcat_user_role table, before creating own acl configurations.
        
        > bin/console onixcat:acl:refresh
                        
       
## Services

### security.resource_provider

    alias for: onixcat_security.acl.resource.provider
    class: Onixcat\Bundle\SecurityBundle\Security\Acl\Resource\ResourceProvider
    
## Usage examples
    
    # In action method
        $this->isGranted('VIEW', $this->container->get('security.resource_provider')->get('group_name.resource_name'));