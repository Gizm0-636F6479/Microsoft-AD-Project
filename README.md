# Active-Directory ReadMe
This repository serves as a personal knowledge base and learning log for mastering Active Directory (AD) concepts, exploitation, and defense techniques. The focus is on practical application within controlled lab environments, primarily using virtual machines through VMware and learning tracks through HTB.

# Active Directory Structure Example
<pre>
ExampleCorp.com (Domain)
├─── Built-in (Default Container)
├─── Computers (Default Container)
├─── Users (Default Container)
└─── Organizational Units (OUs - Custom Management Structure)
    ├─── Infrastructure
    │    ├─── Servers
    │    │    ├─── Production Servers
    │    │    └─── Test/Development Servers
    │    └─── Shared Assets
    │         ├─── Printers (Container)
    │         └─── Service Accounts (Container)
    ├─── Departments
    │    ├─── IT Services
    │    │    ├─── IT Support
    │    │    └─── Network Operations
    │    │    ├─── Users (Container)
    │    │    └─── Computers (Container)
    │    ├─── Finance
    │    │    ├─── Users (Container)
    │    │    └─── Computers (Container)
    │    └─── Sales & Marketing
    │         ├─── Users (Container)
    │         └─── Computers (Container)
    └─── USA (Geographical OU)
         ├─── HQ - Atlanta
         └─── West Coast Offices
</pre>

# Active Directory Key-Terms

* **Core Terms**
    * Forest:	The topmost container; a collection of one or multiple Active Directory domains. Each forest operates independently and contains all AD objects.
    * Domain:	A logical group of objects (computers, users, OUs, groups, etc.). Domains can operate independently or be connected via trust relationships.
    * Tree:	A collection of Active Directory domains that begins at a single root domain. All domains in a tree share a standard Global Catalog and a common namespace boundary.
    * Object:	ANY resource present within an Active Directory environment, such as OUs, printers, users, and domain controllers.
    * Attributes:	An associated set of characteristics used to define a given object (e.g., hostname, DNS name, displayName). All attributes have an associated LDAP name.
    * Schema:	The blueprint of the AD environment. It defines what types of Objects can exist in the AD database and their associated Attributes.
    * Container:	Objects that hold other objects and have a defined place in the directory subtree hierarchy (e.g., Organizational Units, or OUs).
    * Leaf:	Objects that do not contain other objects and are found at the end of the subtree hierarchy (e.g., a specific user or computer).

