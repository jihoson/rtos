<!-- ...................................................................... -->
<!-- XHTML Name Identifier Module  ........................................ -->
<!-- file: xhtml-nameident-1.mod

     This is XHTML, a reformulation of HTML as a modular XML application.
     Copyright 1998-2000 W3C (MIT, INRIA, Keio), All Rights Reserved.
     Revision: $Id: xhtml-nameident-1.mod,v 3.0 2000/10/22 17:13:38 altheim Exp $

     This DTD module is identified by the PUBLIC and SYSTEM identifiers:

       PUBLIC "-//W3C//ELEMENTS XHTML Name Identifier 1.0//EN"
       SYSTEM "http://www.w3.org/TR/xhtml-modularization/DTD/xhtml-nameident-1.mod"

     Revisions:
     (none)
     ....................................................................... -->

<!-- Name Identifier

       'name' attribute on form, img, a, map, applet, frame, iframe

     This module declares the 'name' attribute on element types when 
     it is used as a node identifier for legacy linking and scripting 
     support. This does not include those instances when 'name' is used 
     as a container for form control, property or metainformation names.
     
     This module should be instantiated following all modules it modifies.
-->

<!ENTITY % form.attlist  "IGNORE" >
<![%form.attlist;[
<!ATTLIST %form.qname;
      name         CDATA                    #IMPLIED
>
<!-- end of form.attlist -->]]>

<!ENTITY % img.attlist  "IGNORE" >
<![%img.attlist;[
<!ATTLIST %img.qname;
      name         CDATA                    #IMPLIED
>
<!-- end of img.attlist -->]]>

<!ENTITY % a.attlist  "IGNORE" >
<![%a.attlist;[
<!ATTLIST %a.qname;
      name         CDATA                    #IMPLIED
>
<!-- end of a.attlist -->]]>

<!ENTITY % map.attlist  "IGNORE" >
<![%map.attlist;[
<!ATTLIST %map.qname;
      name         CDATA                    #IMPLIED
>
<!-- end of map.attlist -->]]>

<!ENTITY % applet.attlist  "IGNORE" >
<![%applet.attlist;[
<!ATTLIST %applet.qname;
      name         CDATA                    #IMPLIED
>
<!-- end of applet.attlist -->]]>

<!ENTITY % frame.attlist  "IGNORE" >
<![%frame.attlist;[
<!ATTLIST %frame.qname;
      name         CDATA                    #IMPLIED
>
<!-- end of frame.attlist -->]]>

<!ENTITY % iframe.attlist  "IGNORE" >
<![%iframe.attlist;[
<!ATTLIST %iframe.qname;
      name         CDATA                    #IMPLIED
>
<!-- end of iframe.attlist -->]]>

<!-- end of xhtml-nameident.mod -->
