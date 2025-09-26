/*
 * Licensed to The Apereo Foundation under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 *
 * The Apereo Foundation licenses this file to you under the Educational
 * Community License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package org.opencastproject.security.filter;

import org.apache.shiro.config.Ini;
import org.apache.shiro.lang.util.ClassUtils;
import org.apache.shiro.mgt.AbstractRememberMeManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.session.mgt.eis.MemorySessionDAO;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.web.env.IniWebEnvironment;
import org.apache.shiro.web.filter.authc.PassThruAuthenticationFilter;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ServiceScope;
import org.osgi.service.component.propertytypes.ServiceRanking;
import org.osgi.service.http.whiteboard.propertytypes.HttpWhiteboardContextSelect;
import org.osgi.service.http.whiteboard.propertytypes.HttpWhiteboardFilterName;
import org.osgi.service.http.whiteboard.propertytypes.HttpWhiteboardFilterPattern;

import java.util.Objects;

import javax.servlet.Filter;

@Component(
    service = { Filter.class },
    scope = ServiceScope.PROTOTYPE,
    property = {
        "service.description=Shiro Security Filter",
    }
)
@ServiceRanking(971)
@HttpWhiteboardFilterName("Security2Filter")
@HttpWhiteboardFilterPattern("/*")
@HttpWhiteboardContextSelect("(osgi.http.whiteboard.context.name=opencast)")
public class ShiroSecurityFilter extends AbstractShiroFilter {

  private static final Ini file = new Ini();
  static {
    // Can't use the Ini.fromResourcePath(String) method because it can't find "shiro.ini" on the classpath in
    file.load(Objects.requireNonNull(ShiroSecurityFilter.class.getClassLoader()
        .getResourceAsStream("shiro.ini")));
  }

  private Realm realm;

  // Dependency injected shiro services
  protected SessionDAO session = new MemorySessionDAO();



  @Activate
  public void activate() {
    createShiroWebEnvironmentFromIniFile(getClass().getClassLoader(), file);
  }

  protected void createShiroWebEnvironmentFromIniFile(ClassLoader classLoader, Ini iniFile) {
    try {
      ClassUtils.setAdditionalClassLoader(PassThruAuthenticationFilter.class.getClassLoader());
      var environment = createShiroIniWebEnvironment();
      environment.setIni(iniFile);
      environment.setServletContext(getServletContext());
      environment.init();
      var sessionmanager = new DefaultWebSessionManager();
      sessionmanager.setSessionDAO(session);
      sessionmanager.setSessionIdUrlRewritingEnabled(false);
      var securityManager = (DefaultWebSecurityManager) environment.getWebSecurityManager();
      securityManager.setSessionManager(sessionmanager);
      var t = new IniRealm(iniFile);
      securityManager.setRealm(t);
      var remembermeManager = (AbstractRememberMeManager) securityManager.getRememberMeManager();
      setSecurityManager(securityManager);
      setFilterChainResolver(environment.getFilterChainResolver());
    } finally {
      ClassUtils.removeAdditionalClassLoader();
    }
  }

  /**
   * Override this method to use a different web environment class
   * @return an instance of {@link IniWebEnvironment} or a subclass of {@link IniWebEnvironment}
   */
  protected IniWebEnvironment createShiroIniWebEnvironment() {
    return new IniWebEnvironment();
  }

  @Reference
  public void setRealm(Realm realm) {
    this.realm = realm;
  }


}
