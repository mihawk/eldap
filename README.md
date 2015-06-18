eldap
=====

 extract eldap component from ejabberd 15.04.66

Howto
-----

## clone the repo

```bash
  $ git clone http://github.com/mihawk/eldap
```

## build with [mad](http://github.com/naga-framework/mad)

```bash
  $ mad deps compile 
```

## setting: Active Directory (Microsoft)

```erlang
{eldap, [
         {default, [         
                    {ldap_servers, ["ldap.MyDomain.com"]},
                    {ldap_encrypt, none},
                    {ldap_port, 389},
                    {ldap_uids, [{"sAMAccountName", "%u"}]},
                    {ldap_base, "CN=Users,DC=MyDomain,DC=com"},
                    {ldap_rootdn, "CN=Administrator,CN=Users,DC=MyDomain,DC=com"},
                    {ldap_password, "MyPassword"},
                    {ldap_filter, "(memberOf=*)"}
                   ]
         }
        ]
 }
```

## check password

```bash
>cd eldap
>./start.sh
(eldap@127.0.0.1)1> 
(eldap@127.0.0.1)1> eldap_api:start().
00:55:36.645 [info] LDAP connection on 120.24.93.46:389
00:55:36.646 [info] LDAP connection on 120.24.93.46:389
{ok,<0.86.0>}
(eldap@127.0.0.1)2> eldap_api:check_password(default, <<"username">>, <<"password">>).
true
(eldap@127.0.0.1)3>
```

## fetch user

```bash
  $ cd eldap
  $ ./start.sh
(eldap@127.0.0.1)3> eldap_api:fetch_user(default, <<"username">>).                    
{ok,[{attributes,[{<<"sAMAccountName">>,[<<"username">>]}]},
     {object_name,<<"CN=firstname lastname,CN=Users,DC=MyDomain,DC=com">>}]}
(eldap@127.0.0.1)4> 
```
 


Credits
-------

* [ProcessOne](https://www.process-one.net/en/ejabberd)
* chan sisowath (extracting/packaging)

Links
-----

- Documentation: http://docs.ejabberd.im
- Community site: https://www.ejabberd.im
- ejabberd commercial offering and support: https://www.process-one.net/en/ejabberd
- [active directory information](http://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx)
