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

package org.opencastproject.serviceregistry.impl.endpoint;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

import org.opencastproject.job.api.JaxbJob;
import org.opencastproject.job.api.JaxbJobList;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobParser;
import org.opencastproject.rest.RestConstants;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.serviceregistry.api.HostRegistration;
import org.opencastproject.serviceregistry.api.JaxbHostRegistration;
import org.opencastproject.serviceregistry.api.JaxbHostRegistrationList;
import org.opencastproject.serviceregistry.api.JaxbServiceHealth;
import org.opencastproject.serviceregistry.api.JaxbServiceRegistration;
import org.opencastproject.serviceregistry.api.JaxbServiceRegistrationList;
import org.opencastproject.serviceregistry.api.JaxbServiceStatisticsList;
import org.opencastproject.serviceregistry.api.ServiceRegistration;
import org.opencastproject.serviceregistry.api.ServiceRegistry;
import org.opencastproject.serviceregistry.api.ServiceRegistryException;
import org.opencastproject.serviceregistry.api.ServiceState;
import org.opencastproject.serviceregistry.api.SystemLoad;
import org.opencastproject.serviceregistry.impl.ServiceRegistryJpaImpl;
import org.opencastproject.systems.OpencastConstants;
import org.opencastproject.util.GsonUtil;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.UrlSupport;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;

import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.media.SchemaProperty;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * Displays hosts and the service IDs they provide.
 */
@Path("/services")
@Tag(
    name = "Service Registry",
    description = "Provides registration and management functions for servers and services in this Opencast instance "
        + "or cluster."
)
@Component(
    property = {
      "service.description=Service Registry REST Endpoint",
      "opencast.service.type=org.opencastproject.serviceregistry",
      "opencast.service.path=/services"
    },
    immediate = true,
    service = { ServiceRegistryEndpoint.class }
)
@JaxrsResource
public class ServiceRegistryEndpoint {

  /** The remote service maanger */
  protected ServiceRegistry serviceRegistry = null;

  private SecurityService securityService = null;

  /** This server's URL */
  protected String serverUrl = UrlSupport.DEFAULT_BASE_URL;

  /** The service path for this endpoint */
  protected String servicePath = "/";

  /** Sets the service registry instance for delegation */
  @Reference
  public void setServiceRegistry(ServiceRegistry serviceRegistry) {
    this.serviceRegistry = serviceRegistry;
  }

  @Reference
  public void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }

  /**
   * Callback from OSGi that is called when this service is activated.
   *
   * @param cc
   *          OSGi component context
   */
  @Activate
  public void activate(ComponentContext cc) {
    serverUrl = cc.getBundleContext().getProperty(OpencastConstants.SERVER_URL_PROPERTY);
    servicePath = (String) cc.getProperties().get(RestConstants.SERVICE_PATH_PROPERTY);
  }

  @GET
  @Path("statistics.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get service statistics as JSON",
      description = "List the service registrations in the cluster, along with some simple statistics"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A JSON representation of the service statistics")
  })
  public Response getStatisticsAsJson() {
    try {
      return Response.ok(new JaxbServiceStatisticsList(serviceRegistry.getServiceStatistics())).build();
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e, Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Path("statistics.xml")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Get service statistics as XML",
      description = "List the service registrations in the cluster, along with some simple statistics"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the service statistics")
  })
  public Response getStatisticsAsXml() throws ServiceRegistryException {
    return getStatisticsAsJson();
  }

  @POST
  @Path("sanitize")
  @Operation(
      summary = "Reset a service to the normal state",
      description = "Sets the given service to NORMAL state"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "The service was successfully sanitized"),
      @ApiResponse(responseCode = "404", description = "No service of that type on that host is registered.")
  })
  public Response sanitize(
      @Parameter(description = "The service type identifier", required = true, schema = @Schema(example = ""))
      @FormParam("serviceType") String serviceType,
      @Parameter(
          description = "The host providing the service, including the http(s) protocol",
          required = true,
          schema = @Schema(example = "")
      )
      @FormParam("host") String host
  ) throws NotFoundException {
    serviceRegistry.sanitize(serviceType, host);
    return Response.status(Status.NO_CONTENT).build();
  }

  @POST
  @Path("register")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Register a service",
      description = "Add a new service registration to the cluster."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the new service registration")
  })
  public JaxbServiceRegistration register(
      @Parameter(description = "The service type identifier", required = true, schema = @Schema(example = ""))
      @FormParam("serviceType") String serviceType,
      @Parameter(
          description = "The host providing the service, including the http(s) protocol",
          required = true,
          schema = @Schema(example = "")
      )
      @FormParam("host") String host,
      @Parameter(description = "The service path on the host", required = true, schema = @Schema(example = ""))
      @FormParam("path") String path,
      @Parameter(
          description = "Whether this service is a producer of long running jobs requiring dispatch",
          required = true,
          schema = @Schema(example = "false")
      )
      @FormParam("jobProducer") boolean jobProducer
  ) {
    try {
      return new JaxbServiceRegistration(serviceRegistry.registerService(serviceType, host, path, jobProducer));
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }

  @POST
  @Path("unregister")
  @Operation(
      summary = "Unregister a service",
      description = "Removes a service registration."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "The service was unregistered successfully")
  })
  public Response unregister(
      @Parameter(description = "The service type identifier", required = true)
      @FormParam("serviceType") String serviceType,
      @Parameter(
          description = "The host providing the service, including the http(s) protocol",
          required = true
      )
      @FormParam("host") String host
  ) {
    try {
      serviceRegistry.unRegisterService(serviceType, host);
      return Response.status(Status.NO_CONTENT).build();
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }

  @POST
  @Path("enablehost")
  @Operation(
      summary = "Enable a host",
      description = "Enable a server from the cluster."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "The host was enabled successfully"),
      @ApiResponse(responseCode = "404", description = "The host does not exist")
  })
  public Response enableHost(
      @Parameter(description = "The host name, including the http(s) protocol", required = true)
      @FormParam("host") String host
  ) throws NotFoundException {
    try {
      serviceRegistry.enableHost(host);
      return Response.status(Status.NO_CONTENT).build();
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }

  @POST
  @Path("disablehost")
  @Operation(
      summary = "Disable a host",
      description = "Disable a server from the cluster."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "The host was disabled successfully"),
      @ApiResponse(responseCode = "404", description = "The host does not exist")
  })
  public Response disableHost(
      @Parameter(description = "The host name, including the http(s) protocol", required = true)
      @FormParam("host") String host
  ) throws NotFoundException {
    try {
      serviceRegistry.disableHost(host);
      return Response.status(Status.NO_CONTENT).build();
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }

  @POST
  @Path("registerhost")
  @Operation(
      summary = "Register a host",
      description = "Add a new server to the cluster."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "The host was registered successfully")
  })
  public void register(
      @Parameter(description = "The host name, including the http(s) protocol", required = true)
      @FormParam("host") String host,
      @Parameter(description = "The IP address", required = true)
      @FormParam("address") String address,
      @Parameter(description = "Descriptive node name", required = true)
      @FormParam("nodeName") String nodeName,
      @Parameter(description = "The allocated memory", required = true)
      @FormParam("memory") long memory,
      @Parameter(description = "The available cores", required = true)
      @FormParam("cores") int cores,
      @Parameter(description = "The maximum load this host support", required = true)
      @FormParam("maxLoad") float maxLoad
  ) {
    try {
      serviceRegistry.registerHost(host, address, nodeName, memory, cores, maxLoad);
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }

  @POST
  @Path("unregisterhost")
  @Operation(
      summary = "Unregister a host",
      description = "Removes a server from the cluster."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "The host was removed successfully")
  })
  public Response unregister(
      @Parameter(description = "The host name, including the http(s) protocol", required = true)
      @FormParam("host") String host
  ) {
    try {
      serviceRegistry.unregisterHost(host);
      return Response.status(Status.NO_CONTENT).build();
    } catch (ServiceRegistryException e) {
      if (e.getCause() instanceof IllegalArgumentException) {
        return Response.status(Status.NOT_FOUND).entity(e.getMessage()).build();
      }
      throw new WebApplicationException(e);
    }
  }

  @POST
  @Path("maintenance")
  @Operation(
      summary = "Set the maintenance mode of a host",
      description = "Sets the maintenance status for a server in the cluster."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "The host was registered successfully"),
      @ApiResponse(responseCode = "404", description = "Host not found")
  })
  public Response setMaintenanceMode(
      @Parameter(description = "The host name, including the http(s) protocol", required = true)
      @FormParam("host") String host,
      @Parameter(description = "Whether this host should be put into maintenance mode (true) or not", required = true)
      @FormParam("maintenance") boolean maintenance
  ) throws NotFoundException {
    try {
      serviceRegistry.setMaintenanceStatus(host, maintenance);
      return Response.status(Status.NO_CONTENT).build();
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }

  @GET
  @Path("available.xml")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Get the available services as XML",
      description = "Lists available services by service type identifier, ordered by load."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returned the available services."),
      @ApiResponse(responseCode = "400", description = "No service type specified, bad request.")
  })
  public Response getAvailableServicesAsXml(
      @Parameter(description = "The service type identifier")
      @QueryParam("serviceType") String serviceType
  ) {

    if (isBlank(serviceType)) {
      throw new WebApplicationException(
          Response.status(Status.BAD_REQUEST).entity("Service type must be specified").build());
    }

    Map<String, String> properties = securityService.getOrganization().getProperties();

    JaxbServiceRegistrationList registrations = new JaxbServiceRegistrationList();
    try {
      for (ServiceRegistration reg : serviceRegistry.getServiceRegistrationsByLoad(serviceType)) {
        JaxbServiceRegistration jaxbReg = new JaxbServiceRegistration(reg);
        URL internalHostUrl = URI.create(jaxbReg.getHost()).toURL();
        String tenantSpecificHost = StringUtils.trimToNull(properties.get("org.opencastproject.host."
            + internalHostUrl.getHost()));
        if (StringUtils.isNotBlank(tenantSpecificHost)) {
          jaxbReg.setHost(tenantSpecificHost);
        }
        registrations.add(jaxbReg);
      }
      return Response.ok(registrations).build();
    } catch (ServiceRegistryException | MalformedURLException | IllegalArgumentException e) {
      throw new WebApplicationException(e);
    }
  }

  @GET
  @Path("available.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the available services as JSON",
      description = "Lists available services by service type identifier, ordered by load."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returned the available services."),
      @ApiResponse(responseCode = "400", description = "No service type specified, bad request.")
  })
  public Response getAvailableServicesAsJson(
      @Parameter(description = "The service type identifier")
      @QueryParam("serviceType") String serviceType
  ) {
    return getAvailableServicesAsXml(serviceType);
  }

  @GET
  @Path("health.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the health of the services as JSON",
      description = "Checks the status of the registered services"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Service states returned"),
      @ApiResponse(responseCode = "404", description = "No service of that type on that host is registered."),
      @ApiResponse(responseCode = "503", description = "An error has occurred during stats processing")
  })
  public Response getHealthStatusAsJson(
      @Parameter(description = "The service type identifier")
      @QueryParam("serviceType") String serviceType,
      @Parameter(description = "The host, including the http(s) protocol")
      @QueryParam("host") String host
  ) throws NotFoundException {
    return getHealthStatus(serviceType, host);
  }

  @GET
  @Path("health.xml")
  @Produces(MediaType.APPLICATION_XML)
  @Operation(
      summary = "Get the health of the services as XML",
      description = "Checks the status of the registered services"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Service states returned"),
      @ApiResponse(responseCode = "404", description = "No service of that type on that host is registered."),
      @ApiResponse(responseCode = "503", description = "An error has occurred during stats processing")
  })
  public Response getHealthStatus(
      @Parameter(description = "The service type identifier")
      @QueryParam("serviceType") String serviceType,
      @Parameter(description = "The host, including the http(s) protocol")
      @QueryParam("host") String host
  ) throws NotFoundException {
    try {
      List<ServiceRegistration> services = null;
      if (isNotBlank(serviceType) && isNotBlank(host)) {
        // This is a request for one specific service. Return it, or SC_NOT_FOUND if not found
        ServiceRegistration reg = serviceRegistry.getServiceRegistration(serviceType, host);
        if (reg == null) {
          throw new NotFoundException();
        }

        services = new LinkedList<ServiceRegistration>();
        services.add(reg);
      } else if (isBlank(serviceType) && isBlank(host)) {
        // This is a request for all service registrations
        services = serviceRegistry.getServiceRegistrations();
      } else if (isNotBlank(serviceType)) {
        // This is a request for all service registrations of a particular type
        services = serviceRegistry.getServiceRegistrationsByType(serviceType);
      } else if (isNotBlank(host)) {
        // This is a request for all service registrations of a particular host
        services = serviceRegistry.getServiceRegistrationsByHost(host);
      }

      int healthy = 0;
      int warning = 0;
      int error = 0;
      for (ServiceRegistration reg : services) {
        if (ServiceState.NORMAL == reg.getServiceState()) {
          healthy++;
        } else if (ServiceState.WARNING == reg.getServiceState()) {
          warning++;
        } else if (ServiceState.ERROR == reg.getServiceState()) {
          error++;
        } else {
          error++;
        }
      }
      JaxbServiceHealth stats = new JaxbServiceHealth(healthy, warning, error);
      return Response.ok(stats).build();
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }

  @GET
  @Path("services.xml")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Get service registrations as XML",
      description = "Returns a service registration or list of available service registrations as XML."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returned the available service."),
      @ApiResponse(responseCode = "404", description = "No service of that type on that host is registered.")
  })
  public JaxbServiceRegistrationList getRegistrationsAsXml(
      @Parameter(description = "The service type identifier")
      @QueryParam("serviceType") String serviceType,
      @Parameter(description = "The host, including the http(s) protocol")
      @QueryParam("host") String host
  ) throws NotFoundException {
    JaxbServiceRegistrationList registrations = new JaxbServiceRegistrationList();
    try {
      if (isNotBlank(serviceType) && isNotBlank(host)) {
        // This is a request for one specific service. Return it, or SC_NOT_FOUND if not found
        ServiceRegistration reg = serviceRegistry.getServiceRegistration(serviceType, host);
        if (reg == null) {
          throw new NotFoundException();
        } else {
          return new JaxbServiceRegistrationList(new JaxbServiceRegistration(reg));
        }
      } else if (isBlank(serviceType) && isBlank(host)) {
        // This is a request for all service registrations
        for (ServiceRegistration reg : serviceRegistry.getServiceRegistrations()) {
          registrations.add(new JaxbServiceRegistration(reg));
        }
      } else if (isNotBlank(serviceType)) {
        // This is a request for all service registrations of a particular type
        for (ServiceRegistration reg : serviceRegistry.getServiceRegistrationsByType(serviceType)) {
          registrations.add(new JaxbServiceRegistration(reg));
        }
      } else if (isNotBlank(host)) {
        // This is a request for all service registrations of a particular host
        for (ServiceRegistration reg : serviceRegistry.getServiceRegistrationsByHost(host)) {
          registrations.add(new JaxbServiceRegistration(reg));
        }
      }
      return registrations;
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }

  @GET
  @Path("services.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get service registrations as JSON",
      description = "Returns a service registration or list of available service registrations as JSON."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returned the available service."),
      @ApiResponse(responseCode = "404", description = "No service of that type on that host is registered.")
  })
  public JaxbServiceRegistrationList getRegistrationsAsJson(
      @Parameter(description = "The service type identifier")
      @QueryParam("serviceType") String serviceType,
      @Parameter(description = "The host, including the http(s) protocol")
      @QueryParam("host") String host
  ) throws NotFoundException {
    return getRegistrationsAsXml(serviceType, host);
  }

  @GET
  @Path("hosts.xml")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Get host registrations as XML",
      description = "Returns a host registration or list of available host registrations as XML."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returned the available hosts.")
  })
  public JaxbHostRegistrationList getHostsAsXml() throws NotFoundException {
    JaxbHostRegistrationList registrations = new JaxbHostRegistrationList();
    try {
      for (HostRegistration reg : serviceRegistry.getHostRegistrations()) {
        registrations.add(new JaxbHostRegistration(reg));
      }
      return registrations;
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }

  @GET
  @Path("hosts.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get host registrations as JSON",
      description = "Returns a host registration or list of available host registrations as JSON."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returned the available hosts.")
  })
  public JaxbHostRegistrationList getHostsAsJson() throws NotFoundException {
    return getHostsAsXml();
  }

  @POST
  @Path("job")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Create a job",
      description = "Creates a new job."
  )
  @RequestBody(
      content = {
          @Content(
              mediaType = MediaType.APPLICATION_FORM_URLENCODED,
              schema = @Schema(type = "object", requiredProperties = {"jobType", "host", "operation"}),
              schemaProperties = {
                  @SchemaProperty(
                      name = "jobType",
                      schema = @Schema(
                          type = "string",
                          description = "The job type identifier"
                      )
                  ),
                  @SchemaProperty(
                      name = "host",
                      schema = @Schema(
                          type = "string",
                          description = "The creating host, including the http(s) protocol"
                      )
                  ),
                  @SchemaProperty(
                      name = "operation",
                      schema = @Schema(
                          type = "string",
                          description = "The operation this job should execute"
                      )
                  ),
                  @SchemaProperty(
                      name = "payload",
                      schema = @Schema(
                          type = "string",
                          description = "The payload of the job"
                      )
                  ),
                  @SchemaProperty(
                      name = "start",
                      schema = @Schema(
                          type = "boolean",
                          description = "Whether the job should be queued for dispatch and execution"
                      )
                  ),
                  @SchemaProperty(
                      name = "jobLoad",
                      schema = @Schema(
                          type = "string",
                          description = "The load this job will incur on the system"
                      )
                  ),
                  @SchemaProperty(
                      name = "arg",
                      schema = @Schema(
                          type = "string",
                          description = "An argument for the operation (can be given multiple times)"
                      )
                  )
              }
          )
      }
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "Job created."),
      @ApiResponse(responseCode = "400", description = "The required parameters were not supplied, bad request.")
  })
  public Response createJob(
      @Context HttpServletRequest request
  ) {
    String[] argArray = request.getParameterValues("arg");
    List<String> arguments = null;
    if (argArray != null && argArray.length > 0) {
      arguments = Arrays.asList(argArray);
    }
    String jobType = request.getParameter("jobType");
    String operation = request.getParameter("operation");
    String host = request.getParameter("host");
    String payload = request.getParameter("payload");
    boolean start = StringUtils.isBlank(request.getParameter("start"))
            || Boolean.TRUE.toString().equalsIgnoreCase(request.getParameter("start"));
    try {
      Job job = null;
      if (StringUtils.isNotBlank(request.getParameter("jobLoad"))) {
        Float jobLoad = Float.parseFloat(request.getParameter("jobLoad"));
        job = ((ServiceRegistryJpaImpl) serviceRegistry).createJob(host, jobType, operation, arguments, payload,
              start, serviceRegistry.getCurrentJob(), jobLoad);
      } else {
        job = ((ServiceRegistryJpaImpl) serviceRegistry).createJob(host, jobType, operation, arguments, payload,
                start, serviceRegistry.getCurrentJob());
      }
      return Response.created(job.getUri()).entity(new JaxbJob(job)).build();
    } catch (IllegalArgumentException e) {
      throw new WebApplicationException(Status.BAD_REQUEST);
    } catch (Exception e) {
      throw new WebApplicationException(e);
    }
  }

  @PUT
  @Path("job/{id}.xml")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Update a job",
      description = "Updates an existing job"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "Job updated."),
      @ApiResponse(responseCode = "404", description = "Job not found.")
  })
  public Response updateJob(
      @Parameter(description = "The job identifier", required = true)
      @PathParam("id") String id,
      @Parameter(description = "The updated job as XML", required = true)
      @FormParam("job") String jobXml
  ) throws NotFoundException {
    try {
      Job job = JobParser.parseJob(jobXml);
      serviceRegistry.updateJob(job);
      return Response.status(Status.NO_CONTENT).build();
    } catch (Exception e) {
      throw new WebApplicationException(e);
    }
  }

  @GET
  @Path("job/{id}.xml")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Get a job as XML",
      description = "Returns a job as XML."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Job found."),
      @ApiResponse(responseCode = "404", description = "No job with that identifier exists.")
  })
  public JaxbJob getJobAsXml(
      @Parameter(description = "The job identifier", required = true)
      @PathParam("id") long id
  ) throws NotFoundException {
    return getJobAsJson(id);
  }

  @GET
  @Path("job/{id}.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get a job as JSON",
      description = "Returns a job as JSON."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Job found."),
      @ApiResponse(responseCode = "404", description = "No job with that identifier exists.")
  })
  public JaxbJob getJobAsJson(
      @Parameter(description = "The job identifier", required = true)
      @PathParam("id") long id
  ) throws NotFoundException {
    try {
      return new JaxbJob(serviceRegistry.getJob(id));
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }

  @GET
  @Path("job/{id}/children.xml")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Get the descendants of a job as XML",
      description = "Returns all descendants (children, their children and so on) of a job as XML."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Jobs found.")
  })
  public JaxbJobList getChildrenJobsAsXml(
      @Parameter(description = "The ancestor job identifier", required = true)
      @PathParam("id") long id
  ) {
    return getChildrenJobsAsJson(id);
  }

  @GET
  @Path("job/{id}/children.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the descendants of a job as JSON",
      description = "Returns all descendants (children, their children and so on) of a job as JSON."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Jobs found.")
  })
  public JaxbJobList getChildrenJobsAsJson(
      @Parameter(description = "The ancestor job identifier", required = true)
      @PathParam("id") long id
  ) {
    try {
      return new JaxbJobList(serviceRegistry.getDescendantJobs(id));
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }

  @GET
  @Path("jobs.xml")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Get jobs as XML",
      description = "Returns the jobs matching the query parameters as XML."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Jobs found.")
  })
  public JaxbJobList getJobsAsXml(
      @Parameter(description = "The service type identifier")
      @QueryParam("serviceType") String serviceType,
      @Parameter(description = "The job status")
      @QueryParam("status") Job.Status status
  ) {
    try {
      return new JaxbJobList(serviceRegistry.getJobs(serviceType, status));
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }

  }

  @GET
  @Path("activeJobs.xml")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Get active jobs as XML",
      description = "Returns all active jobs as XML."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Active jobs found.")
  })
  public JaxbJobList getActiveJobsAsXml() {
    try {
      return new JaxbJobList(serviceRegistry.getActiveJobs());
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }

  @GET
  @Path("activeJobs.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get active jobs as JSON",
      description = "Returns all active jobs as JSON."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Active jobs found.")
  })
  public JaxbJobList getActiveJobsAsJson() {
    try {
      return new JaxbJobList(serviceRegistry.getActiveJobs());
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }

  @GET
  @Path("count")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Get the number of jobs",
      description = "Returns the number of jobs matching the query parameters as plain text."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Job count returned.")
  })
  public long count(
      @Parameter(description = "The service type identifier")
      @QueryParam("serviceType") String serviceType,
      @Parameter(description = "The job status")
      @QueryParam("status") Job.Status status,
      @Parameter(description = "The host executing the job")
      @QueryParam("host") String host,
      @Parameter(description = "The job's operation")
      @QueryParam("operation") String operation
  ) {
    try {
      if (isNotBlank(host) && isNotBlank(operation)) {
        if (isBlank(serviceType)) {
          throw new WebApplicationException(Response.serverError().entity("Service type must not be null").build());
        }
        return serviceRegistry.count(serviceType, host, operation, status);
      } else if (isNotBlank(host)) {
        if (isBlank(serviceType)) {
          throw new WebApplicationException(Response.serverError().entity("Service type must not be null").build());
        }
        return serviceRegistry.countByHost(serviceType, host, status);
      } else if (isNotBlank(operation)) {
        if (isBlank(serviceType)) {
          throw new WebApplicationException(Response.serverError().entity("Service type must not be null").build());
        }
        return serviceRegistry.countByOperation(serviceType, operation, status);
      } else {
        return serviceRegistry.count(serviceType, status);
      }
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }

  @GET
  @Path("maxconcurrentjobs")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Get the maximum number of concurrent jobs",
      description = "Returns the number of jobs that the servers in this service registry can execute concurrently. "
          + "If there is only one server in this service registry this will be the number of jobs that one server is "
          + "able to do at one time. If it is a distributed install across many servers then this number will be the "
          + "total number of jobs the cluster can process concurrently."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Maximum number of concurrent jobs returned.")
  })
  @Deprecated
  public Response getMaximumConcurrentWorkflows() {
    return Response.status(Status.MOVED_PERMANENTLY).type(MediaType.TEXT_PLAIN)
            .header("Location", servicePath + "/maxload").build();
  }

  @GET
  @Path("maxload")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Get the maximum load",
      description = "Returns the maximum load that servers in this service registry can execute concurrently.  "
          + "If there is only one server in this service registry this will be the maximum load that one server is "
          + "able to handle at one time. If it is a distributed install across many servers then this number will be "
          + "the maximum load the cluster can process concurrently."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Maximum load for the cluster.")
  })
  public Response getMaxLoadOnNode(
      @Parameter(description = "The host you want to know the maximum load for.")
      @QueryParam("host") String host
  ) throws NotFoundException {
    try {
      if (StringUtils.isEmpty(host)) {
        return Response.ok(serviceRegistry.getMaxLoads()).build();
      } else {
        SystemLoad systemLoad = new SystemLoad();
        systemLoad.addNodeLoad(serviceRegistry.getMaxLoadOnNode(host));
        return Response.ok(systemLoad).build();
      }
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }

  @GET
  @Path("currentload")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Get the current load",
      description = "Returns the current load on the servers in this service registry.  "
          + "If there is only one server in this service registry this will be the the load that one server.  "
          + "If it is a distributed install across many servers then this number will be a dictionary of the load on "
          + "all nodes in the cluster."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Current load for the cluster.")
  })
  public Response getCurrentLoad() {
    try {
      return Response.ok(serviceRegistry.getCurrentHostLoads()).build();
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }

  @GET
  @Path("ownload")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Get the load of this node",
      description = "Returns the current load on this service registry's node."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Current load for the cluster.")
  })
  public Response getOwnLoad() {
    try {
      return Response.ok(serviceRegistry.getOwnLoad()).build();
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }


  @DELETE
  @Path("job/{id}")
  @Operation(
      summary = "Delete a job",
      description = "Deletes a job from the service registry"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "Job successfully deleted"),
      @ApiResponse(responseCode = "404", description = "Job with given id could not be found")
  })
  public Response deleteJob(
      @Parameter(description = "ID of the job to delete", required = true)
      @PathParam("id") long id
  ) throws NotFoundException {
    try {
      serviceRegistry.removeJobs(Collections.singletonList(id));
      return Response.noContent().build();
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }


  @POST
  @Path("removejobs")
  @Operation(
      summary = "Remove jobs",
      description = "Removes all given jobs and their child jobs"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "Jobs successfully removed"),
      @ApiResponse(responseCode = "400", description = "jobIds is not a JSON array of identifiers"),
      @ApiResponse(responseCode = "500", description = "Error while removing jobs")
  })
  public Response removeParentlessJobs(
      @Parameter(description = "The IDs of the jobs to delete", required = true)
      @FormParam("jobIds") String jobIds
  ) throws NotFoundException {
    final List<Long> jobIdList = new ArrayList<>();
    try {
      final JsonArray array = GsonUtil.gson().fromJson(jobIds, JsonArray.class);
      if (array == null) {
        throw new JsonParseException("jobIds is empty");
      }
      for (JsonElement id : array) {
        jobIdList.add(id.getAsLong());
      }
    } catch (JsonParseException | IllegalStateException | NumberFormatException e) {
      return Response.status(Status.BAD_REQUEST).entity("jobIds must be a JSON array of job identifiers").build();
    }
    try {
      serviceRegistry.removeJobs(jobIdList);
      return Response.noContent().build();
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }


  @POST
  @Path("removeparentlessjobs")
  @Operation(
      summary = "Remove expired jobs without a parent",
      description = "Removes all jobs without a parent job which have passed their lifetime"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "Parentless jobs successfully removed"),
      @ApiResponse(responseCode = "500", description = "Error while removing parentless jobs")
  })
  public Response removeParentlessJobs(
      @Parameter(description = "Lifetime of parentless jobs", required = true)
      @FormParam("lifetime") int lifetime
  ) {
    try {
      serviceRegistry.removeParentlessJobs(lifetime);
      return Response.noContent().build();
    } catch (ServiceRegistryException e) {
      throw new WebApplicationException(e);
    }
  }

}
