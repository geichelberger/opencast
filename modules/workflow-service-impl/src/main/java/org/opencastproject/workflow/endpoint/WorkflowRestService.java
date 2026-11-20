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

package org.opencastproject.workflow.endpoint;


import org.opencastproject.job.api.JobProducer;
import org.opencastproject.mediapackage.MediaPackage;
import org.opencastproject.mediapackage.MediaPackageElement;
import org.opencastproject.mediapackage.MediaPackageImpl;
import org.opencastproject.mediapackage.MediaPackageParser;
import org.opencastproject.mediapackage.MediaPackageSupport;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.rest.RestConstants;
import org.opencastproject.security.api.Permissions;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.serviceregistry.api.ServiceRegistry;
import org.opencastproject.systems.OpencastConstants;
import org.opencastproject.util.GsonUtil;
import org.opencastproject.util.LocalHashMap;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.UrlSupport;
import org.opencastproject.workflow.api.JaxbWorkflowInstance;
import org.opencastproject.workflow.api.WorkflowDatabaseException;
import org.opencastproject.workflow.api.WorkflowDefinition;
import org.opencastproject.workflow.api.WorkflowDefinitionSet;
import org.opencastproject.workflow.api.WorkflowException;
import org.opencastproject.workflow.api.WorkflowInstance;
import org.opencastproject.workflow.api.WorkflowInstance.WorkflowState;
import org.opencastproject.workflow.api.WorkflowOperationHandler;
import org.opencastproject.workflow.api.WorkflowParsingException;
import org.opencastproject.workflow.api.WorkflowService;
import org.opencastproject.workflow.api.WorkflowSetImpl;
import org.opencastproject.workflow.api.WorkflowStateException;
import org.opencastproject.workflow.api.XmlWorkflowParser;
import org.opencastproject.workflow.impl.WorkflowServiceImpl;
import org.opencastproject.workflow.impl.WorkflowServiceImpl.HandlerRegistration;
import org.opencastproject.workspace.api.Workspace;

import com.google.common.util.concurrent.Striped;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.Lock;

import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * A REST endpoint for the {@link WorkflowService}
 */
@Path("/workflow")
@Tag(
    name = "Workflow Service",
    description = "This service lists available workflows and starts, stops, suspends and resumes workflow instances."
)
@Component(
    immediate = true,
    service = WorkflowRestService.class,
    property = {
        "service.description=Workflow REST Endpoint",
        "opencast.service.type=org.opencastproject.workflow",
        "opencast.service.path=/workflow",
        "opencast.service.jobproducer=true"
    }
)
@JaxrsResource
public class WorkflowRestService extends AbstractJobProducerEndpoint {

  /** The default number of results returned */
  private static final int DEFAULT_LIMIT = 20;
  /** The constant used to negate a querystring parameter. This is only supported on some parameters. */
  public static final String NEGATE_PREFIX = "-";
  /** The constant used to switch the direction of the sorting querystring parameter. */
  public static final String DESCENDING_SUFFIX = "_DESC";
  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(WorkflowRestService.class);

  /** The default server URL */
  protected String serverUrl = UrlSupport.DEFAULT_BASE_URL;
  /** The default service URL */
  protected String serviceUrl = serverUrl + "/workflow";
  /** The workflow service instance */
  private WorkflowService service;
  /** The service registry */
  protected ServiceRegistry serviceRegistry = null;
  /** The workspace */
  private Workspace workspace;

  /** Resource lock */
  private final Striped<Lock> lock = Striped.lazyWeakLock(1024);

  /**
   * Callback from the OSGi declarative services to set the service registry.
   *
   * @param serviceRegistry
   *          the service registry
   */
  @Reference
  protected void setServiceRegistry(ServiceRegistry serviceRegistry) {
    this.serviceRegistry = serviceRegistry;
  }

  /**
   * Sets the workflow service
   *
   * @param service
   *          the workflow service instance
   */
  @Reference
  public void setService(WorkflowService service) {
    this.service = service;
  }

  /**
   * Callback from the OSGi declarative services to set the workspace.
   *
   * @param workspace
   *          the workspace
   */
  @Reference
  public void setWorkspace(Workspace workspace) {
    this.workspace = workspace;
  }

  /**
   * OSGI callback for component activation
   *
   * @param cc
   *          the OSGI declarative services component context
   */
  @Activate
  public void activate(ComponentContext cc) {
    // Get the configured server URL
    if (cc == null) {
      serverUrl = UrlSupport.DEFAULT_BASE_URL;
    } else {
      String ccServerUrl = cc.getBundleContext().getProperty(OpencastConstants.SERVER_URL_PROPERTY);
      logger.info("configured server url is {}", ccServerUrl);
      if (ccServerUrl == null) {
        serverUrl = UrlSupport.DEFAULT_BASE_URL;
      } else {
        serverUrl = ccServerUrl;
      }
      serviceUrl = (String) cc.getProperties().get(RestConstants.SERVICE_PATH_PROPERTY);
    }
  }

  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @Path("/count")
  @Operation(
      summary = "Count workflow instances",
      description = "Returns the number of workflow instances in a specific state"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The number of workflow instances.")
  })
  public Response getCount(
      @Parameter(description = "The workflow state")
      @QueryParam("state") WorkflowInstance.WorkflowState state,
      @QueryParam("operation") String operation
  ) {
    try {
      Long count = service.countWorkflowInstances(state);
      return Response.ok(count).build();
    } catch (WorkflowDatabaseException e) {
      throw new WebApplicationException(e);
    }
  }

  @GET
  @Path("definitions.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "List the workflow definitions as JSON",
      description = "List all available workflow definitions as JSON"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The workflow definitions.")
  })
  public WorkflowDefinitionSet getWorkflowDefinitionsAsJson() throws Exception {
    return getWorkflowDefinitionsAsXml();
  }

  @GET
  @Path("definitions.xml")
  @Produces(MediaType.APPLICATION_XML)
  @Operation(
      summary = "List the workflow definitions as XML",
      description = "List all available workflow definitions as XML"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The workflow definitions.")
  })
  public WorkflowDefinitionSet getWorkflowDefinitionsAsXml() throws Exception {
    List<WorkflowDefinition> list = service.listAvailableWorkflowDefinitions();
    return new WorkflowDefinitionSet(list);
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("definition/{id}.json")
  @Operation(
      summary = "Get a workflow definition as JSON",
      description = "Returns a single workflow definition"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The workflow definition."),
      @ApiResponse(responseCode = "404", description = "Workflow definition not found.")
  })
  public Response getWorkflowDefinitionAsJson(
      @Parameter(description = "The workflow definition identifier", required = true)
      @PathParam("id") String workflowDefinitionId
  ) throws NotFoundException {
    WorkflowDefinition def;
    try {
      def = service.getWorkflowDefinitionById(workflowDefinitionId);
    } catch (WorkflowDatabaseException e) {
      throw new WebApplicationException(e);
    }
    return Response.ok(def).build();
  }

  @GET
  @Produces(MediaType.TEXT_XML)
  @Path("definition/{id}.xml")
  @Operation(
      summary = "Get a workflow definition as XML",
      description = "Returns a single workflow definition"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The workflow definition."),
      @ApiResponse(responseCode = "404", description = "Workflow definition not found.")
  })
  public Response getWorkflowDefinitionAsXml(
      @Parameter(description = "The workflow definition identifier", required = true)
      @PathParam("id") String workflowDefinitionId
  ) throws NotFoundException {
    return getWorkflowDefinitionAsJson(workflowDefinitionId);
  }

  /**
   * Returns the workflow configuration panel HTML snippet for the workflow definition specified by
   *
   * @param definitionId
   * @return config panel HTML snippet
   */
  @GET
  @Produces(MediaType.TEXT_HTML)
  @Path("configurationPanel")
  @Operation(
      summary = "Get the configuration panel of a workflow definition",
      description = "Get the configuration panel for a specific workflow"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The workflow configuration panel.")
  })
  public Response getConfigurationPanel(
      @Parameter(description = "The workflow definition identifier")
      @QueryParam("definitionId") String definitionId
  ) throws NotFoundException {
    try {
      final WorkflowDefinition def = service.getWorkflowDefinitionById(definitionId);
      final String out = def.getConfigurationPanel();
      return Response.ok(out).build();
    } catch (WorkflowDatabaseException e) {
      throw new WebApplicationException(Status.INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("mediaPackage/{id}/hasActiveWorkflows")
  @Operation(
      summary = "Check whether a media package has active workflows",
      description = "Returns if a media package has active workflows"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Whether the media package has active workflows.")
  })
  public Response mediaPackageHasActiveWorkflows(
      @Parameter(description = "The media package identifier", required = true)
      @PathParam("id") String mediaPackageId
  ) {
    try {
      return Response.ok(Boolean.toString(service.mediaPackageHasActiveWorkflows(mediaPackageId))).build();

    } catch (WorkflowDatabaseException e) {
      throw new WebApplicationException(Status.INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Produces({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
  @Path("mediaPackage/{id}/instances.{format:xml|json}")
  @Operation(
      summary = "Get the workflow instances of a media package",
      description = "Returns the workflows for a media package"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns the workflows for a media package."),
      @ApiResponse(responseCode = "403", description = "Not authorized to access the workflows.")
  })
  public Response getWorkflowsOfMediaPackage(
      @Parameter(description = "The media package identifier", required = true)
      @PathParam("id") String mediaPackageId,
      @Parameter(description = "The output format (json or xml) of the response body.", required = true)
      @PathParam("format") String format
  ) {
    try {
      return Response.ok(new WorkflowSetImpl(service.getWorkflowInstancesByMediaPackage(mediaPackageId)))
          .type(toMediaType(format)).build();
    } catch (UnauthorizedException e) {
      return Response.status(Status.FORBIDDEN).build();
    } catch (WorkflowDatabaseException e) {
      throw new WebApplicationException(Status.INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Produces({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
  @Path("mediaPackage/{id}/currentInstance.{format:xml|json}")
  @Operation(
      summary = "Get the current workflow instance of a media package",
      description = "Returns the current workflow for a media package"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns the workflows for a media package."),
      @ApiResponse(responseCode = "400", description = "Unknown action."),
      @ApiResponse(responseCode = "403", description = "Not authorized to access the workflow."),
      @ApiResponse(responseCode = "404", description = "Current workflow not found.")
  })
  public Response getRunningWorkflowOfMediaPackage(
      @Parameter(description = "The media package identifier", required = true)
      @PathParam("id") String mediaPackageId,
      @Parameter(description = "The output format (json or xml) of the response body.", required = true)
      @PathParam("format") String format,
      @Parameter(
          description = "The permission the user needs on the workflow: read, write or contribute",
          example = "read"
      )
      @QueryParam("action") String action
  ) {
    final Permissions.Action requiredAction;
    try {
      requiredAction = StringUtils.isBlank(action)
          ? Permissions.Action.READ
          : Permissions.Action.getEnum(action.trim());
    } catch (IllegalArgumentException e) {
      return Response.status(Status.BAD_REQUEST).build();
    }
    try {
      Optional<WorkflowInstance> optWorkflowInstance = service
          .getRunningWorkflowInstanceByMediaPackage(mediaPackageId, requiredAction.toString());
      if (optWorkflowInstance.isPresent()) {
        return Response.ok(new JaxbWorkflowInstance(optWorkflowInstance.get())).type(toMediaType(format)).build();
      } else {
        return Response.status(Status.NOT_FOUND).build();
      }

    } catch (UnauthorizedException e) {
      return Response.status(Status.FORBIDDEN).build();
    } catch (WorkflowException e) {
      throw new WebApplicationException(Status.INTERNAL_SERVER_ERROR);
    }
  }

  /** The media type of a response in the given format, which is either "json" or "xml" */
  private static String toMediaType(String format) {
    return "json".equals(format) ? MediaType.APPLICATION_JSON : MediaType.APPLICATION_XML;
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("user/{id}/hasActiveWorkflows")
  @Operation(
      summary = "Check whether a user has active workflows",
      description = "Returns if there are currently workflow(s) running that were started by the given user"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Whether there are active workflow for the user.")
  })
  public Response userHasActiveWorkflows(
      @Parameter(description = "The user identifier", required = true)
      @PathParam("id") String userId
  ) {
    try {
      return Response.ok(Boolean.toString(service.userHasActiveWorkflows(userId))).build();

    } catch (WorkflowDatabaseException e) {
      throw new WebApplicationException(Status.INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Produces(MediaType.TEXT_XML)
  @Path("instance/{id}.xml")
  @Operation(
      summary = "Get a workflow instance as XML",
      description = "Get a specific workflow instance."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the workflow instance."),
      @ApiResponse(responseCode = "404", description = "No workflow instance with that identifier exists.")
  })
  public JaxbWorkflowInstance getWorkflowAsXml(
      @Parameter(description = "The workflow instance identifier", required = true)
      @PathParam("id") long id
  ) throws WorkflowDatabaseException, NotFoundException, UnauthorizedException {
    return new JaxbWorkflowInstance(service.getWorkflowById(id));
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("instance/{id}.json")
  @Operation(
      summary = "Get a workflow instance as JSON",
      description = "Get a specific workflow instance."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A JSON representation of the workflow instance."),
      @ApiResponse(responseCode = "404", description = "No workflow instance with that identifier exists.")
  })
  public JaxbWorkflowInstance getWorkflowAsJson(
      @Parameter(description = "The workflow instance identifier", required = true)
      @PathParam("id") long id
  ) throws WorkflowDatabaseException, NotFoundException, UnauthorizedException {
    return getWorkflowAsXml(id);
  }

  @POST
  @Path("start")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Start a workflow instance",
      description = "Start a new workflow instance."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the new workflow instance."),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to start the workflow. Maybe you need to authenticate."
      ),
      @ApiResponse(responseCode = "404", description = "If the parent workflow does not exist")
  })
  public JaxbWorkflowInstance start(
      @Parameter(
          description = "The workflow definition ID or an XML representation of a workflow definition",
          required = true
      )
      @FormParam("definition") String workflowDefinitionXmlOrId,
      @Parameter(
          description = "The XML representation of a mediapackage",
          required = true,
          schema = @Schema(type = "string")
      )
      @FormParam("mediapackage") MediaPackageImpl mp,
      @Parameter(
          description = "An optional parent workflow instance identifier"
      )
      @FormParam("parent") String parentWorkflowId,
      @Parameter(
          description = "An optional set of key=value properties, one per line",
          schema = @Schema(type = "string")
      )
      @FormParam("properties") LocalHashMap localMap
  ) {
    if (mp == null || StringUtils.isBlank(workflowDefinitionXmlOrId)) {
      throw new WebApplicationException(Status.BAD_REQUEST);
    }
    // The media package form parameter is converted by JAX-RS through
    // MediaPackageImpl.valueOf(String), which already validates the identifiers; repeat the
    // check here so the endpoint stays safe even if the conversion path ever changes.
    try {
      MediaPackageSupport.checkPathSafety(mp);
    } catch (IllegalArgumentException e) {
      throw new WebApplicationException(e, Status.BAD_REQUEST);
    }

    WorkflowDefinition workflowDefinition;
    try {
      workflowDefinition = service.getWorkflowDefinitionById(workflowDefinitionXmlOrId);
    } catch (Exception e) {
      // Not an ID. Let's try if it's an XML definition
      try {
        workflowDefinition = XmlWorkflowParser.parseWorkflowDefinition(workflowDefinitionXmlOrId);
      } catch (WorkflowParsingException wpe) {
        throw new WebApplicationException(wpe, Status.BAD_REQUEST);
      }
    }

    WorkflowInstance instance = null;
    try {
      instance = startWorkflow(workflowDefinition, mp, parentWorkflowId, localMap);
    } catch (UnauthorizedException e) {
      throw new WebApplicationException(e, Status.UNAUTHORIZED);
    }
    return new JaxbWorkflowInstance(instance);
  }

  private WorkflowInstance startWorkflow(WorkflowDefinition workflowDefinition, MediaPackageImpl mp,
          String parentWorkflowId, LocalHashMap localMap) throws UnauthorizedException {
    Map<String, String> properties = new HashMap<String, String>();
    if (localMap != null) {
      properties = localMap.getMap();
    }

    Long parentIdAsLong = null;
    if (StringUtils.isNotEmpty(parentWorkflowId)) {
      try {
        parentIdAsLong = Long.parseLong(parentWorkflowId);
      } catch (NumberFormatException e) {
        throw new WebApplicationException(e, Status.BAD_REQUEST);
      }
    }

    try {
      return (WorkflowInstance) service.start(workflowDefinition, mp, parentIdAsLong, properties);
    } catch (WorkflowException e) {
      throw new WebApplicationException(e);
    } catch (NotFoundException e) {
      throw new WebApplicationException(e);
    }
  }

  @POST
  @Path("stop")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Stop a workflow instance",
      description = "Stops a workflow instance."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the stopped workflow instance."),
      @ApiResponse(
          responseCode = "404",
          description = "No running workflow instance with that identifier exists."
      )
  })
  public JaxbWorkflowInstance stop(
      @Parameter(description = "The workflow instance identifier", required = true)
      @FormParam("id") long workflowInstanceId
  ) throws WorkflowException, NotFoundException, UnauthorizedException {
    WorkflowInstance instance = service.stop(workflowInstanceId);
    return new JaxbWorkflowInstance(instance);
  }

  @DELETE
  @Path("remove/{id}")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Remove a workflow instance",
      description = "Danger! Permanently removes a workflow instance including all its child jobs. In most "
          + "circumstances, /stop is what you should use."
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "204",
          description = "If workflow instance could be removed successfully, no content is returned"
      ),
      @ApiResponse(responseCode = "404", description = "No workflow instance with that identifier exists."),
      @ApiResponse(
          responseCode = "403",
          description = "It's not allowed to remove other workflow instance "
              + "statuses than STOPPED, SUCCEEDED and FAILED (use force parameter to override AT YOUR OWN RISK)."
      )
  })
  public Response remove(
      @Parameter(description = "The workflow instance identifier", required = true)
      @PathParam("id") long workflowInstanceId,
      @Parameter(
          description = "If the workflow status should be ignored and the workflow removed anyway",
          example = "false"
      )
      @QueryParam("force") boolean force
  ) throws WorkflowException, NotFoundException, UnauthorizedException {
    try {
      service.remove(workflowInstanceId, force);
    } catch (WorkflowStateException e) {
      return Response.status(Status.FORBIDDEN).build();
    }
    return Response.noContent().build();
  }

  @POST
  @Path("suspend")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Suspend a workflow instance",
      description = "Suspends a workflow instance."
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "An XML representation of the suspended workflow instance."
      ),
      @ApiResponse(
          responseCode = "404",
          description = "No running workflow instance with that identifier exists."
      )
  })
  public Response suspend(
      @Parameter(description = "The workflow instance identifier", required = true)
      @FormParam("id") long workflowInstanceId
  ) throws NotFoundException, UnauthorizedException {
    try {
      WorkflowInstance workflow = service.suspend(workflowInstanceId);
      return Response.ok(new JaxbWorkflowInstance(workflow)).build();
    } catch (WorkflowException e) {
      throw new WebApplicationException(e);
    }
  }

  @POST
  @Path("resume")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Resume a workflow instance",
      description = "Resumes a suspended workflow instance."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the resumed workflow instance."),
      @ApiResponse(responseCode = "409", description = "Can not resume workflow not in paused state"),
      @ApiResponse(
          responseCode = "404",
          description = "No suspended workflow instance with that identifier exists."
      ),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to resume. Maybe you need to authenticate."
      )
  })
  public Response resume(
      @Parameter(description = "The workflow instance identifier", required = true)
      @FormParam("id") long workflowInstanceId,
      @Parameter(
          description = "An optional set of key=value properties, one per line",
          schema = @Schema(type = "string")
      )
      @FormParam("properties") LocalHashMap properties
  ) throws NotFoundException, UnauthorizedException {
    return resume(workflowInstanceId, null, properties);
  }

  @POST
  @Path("replaceAndresume")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Replace the media package of a workflow instance and resume it",
      description = "Replaces a suspended workflow instance with an updated version, and resumes the workflow."
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "An XML representation of the updated and resumed workflow instance."
      ),
      @ApiResponse(responseCode = "409", description = "Can not resume workflow not in paused state"),
      @ApiResponse(
          responseCode = "404",
          description = "No suspended workflow instance with that identifier exists."
      ),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to resume. Maybe you need to authenticate."
      )
  })
  public Response resume(
      @Parameter(description = "The workflow instance identifier", required = true)
      @FormParam("id") long workflowInstanceId,
      @Parameter(description = "The new Mediapackage")
      @FormParam("mediapackage") final String mediaPackage,
      @Parameter(
          description = "An optional set of key=value properties, one per line",
          schema = @Schema(type = "string")
      )
      @FormParam("properties") LocalHashMap properties
  ) throws NotFoundException, UnauthorizedException {
    final Map<String, String> map;
    if (properties == null) {
      map = new HashMap<String, String>();
    } else {
      map = properties.getMap();
    }
    final Lock lock = this.lock.get(workflowInstanceId);
    lock.lock();
    try {
      WorkflowInstance workflow = service.getWorkflowById(workflowInstanceId);
      if (!WorkflowState.PAUSED.equals(workflow.getState())) {
        logger.warn("Can not resume workflow '{}', not in state paused but {}", workflow, workflow.getState());
        return Response.status(Status.CONFLICT).build();
      }

      if (mediaPackage != null) {
        MediaPackage newMp = MediaPackageParser.getFromXml(mediaPackage);
        MediaPackage oldMp = workflow.getMediaPackage();

        // Delete removed elements from workspace
        for (MediaPackageElement elem : oldMp.getElements()) {
          if (MediaPackageSupport.contains(elem.getIdentifier(), newMp)) {
            continue;
          }
          try {
            workspace.delete(elem.getURI());
            logger.info("Deleted removed mediapackge element {}", elem);
          } catch (NotFoundException e) {
            logger.info("Removed mediapackage element {} is already deleted", elem);
          }
        }

        workflow.setMediaPackage(newMp);
        service.update(workflow);
      }
      workflow = service.resume(workflowInstanceId, map);
      return Response.ok(new JaxbWorkflowInstance(workflow)).build();
    } catch (NotFoundException e) {
      return Response.status(Status.NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      return Response.status(Status.UNAUTHORIZED).build();
    } catch (IllegalStateException e) {
      logger.warn(ExceptionUtils.getMessage(e));
      return Response.status(Status.CONFLICT).build();
    } catch (WorkflowException e) {
      logger.error(ExceptionUtils.getMessage(e), e);
      return Response.serverError().build();
    } catch (Exception e) {
      logger.error(ExceptionUtils.getMessage(e), e);
      return Response.serverError().build();
    }
    finally {
      lock.unlock();
    }
  }

  @POST
  @Path("update")
  @Operation(
      summary = "Update a workflow instance",
      description = "Updates a workflow instance."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "Workflow instance updated.")
  })
  public Response update(
      @Parameter(
          description = "The XML representation of the workflow instance.",
          required = true
      )
      @FormParam("workflow") String workflowInstance
  ) throws NotFoundException, UnauthorizedException {
    try {
      WorkflowInstance instance = XmlWorkflowParser.parseWorkflowInstance(workflowInstance);
      service.update(instance);
      return Response.noContent().build();
    } catch (WorkflowException e) {
      throw new WebApplicationException(e);
    }
  }

  @GET
  @Path("handlers.json")
  @SuppressWarnings("unchecked")
  @Operation(
      summary = "List the workflow operation handlers",
      description = "List all registered workflow operation handlers (implementations)."
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "A JSON representation of the registered workflow operation handlers"
      )
  })
  public Response getOperationHandlers() {
    JsonArray jsonArray = new JsonArray();
    for (HandlerRegistration reg : ((WorkflowServiceImpl) service).getRegisteredHandlers()) {
      WorkflowOperationHandler handler = reg.getHandler();
      JsonObject jsonHandler = new JsonObject();
      jsonHandler.addProperty("id", handler.getId());
      jsonHandler.addProperty("description", handler.getDescription());
      jsonArray.add(jsonHandler);
    }
    return Response.ok(jsonArray.toString()).header("Content-Type", MediaType.APPLICATION_JSON).build();
  }

  @GET
  @Path("statemappings.json")
  @Operation(
      summary = "Get the workflow state mappings",
      description = "Get all workflow state mappings"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A JSON representation of the workflow state mappings")
  })
  public Response getStateMappings() {
    return Response.ok(GsonUtil.gson().toJson(service.getWorkflowStateMappings()))
        .header("Content-Type", MediaType.APPLICATION_JSON).build();
  }

  @Path("/cleanup")
  @Operation(
      summary = "Clean up workflow instances",
      description = "Cleans up workflow instances"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Cleanup OK"),
      @ApiResponse(responseCode = "400", description = "Couldn't parse given state"),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to cleanup. Maybe you need to authenticate."
      ),
      @ApiResponse(
          responseCode = "403",
          description = "It's not allowed to delete other workflow "
              + "instance statuses than STOPPED, SUCCEEDED and FAILED"
      )
  })
  public Response cleanup(
      @Parameter(
          description = "Lifetime (buffer) in days a workflow instance should live",
          required = true,
          schema = @Schema(example = "30")
      )
      @FormParam("buffer") int buffer,
      @Parameter(
          description = "Workflow instance state, only STOPPED, SUCCEEDED and FAILED are allowed values here",
          required = true
      )
      @FormParam("state") String stateParam
  ) throws UnauthorizedException {

    WorkflowInstance.WorkflowState state;
    try {
      state = WorkflowInstance.WorkflowState.valueOf(stateParam);
    } catch (IllegalArgumentException e) {
      return Response.status(Status.BAD_REQUEST).build();
    }

    if (state != WorkflowInstance.WorkflowState.SUCCEEDED && state != WorkflowInstance.WorkflowState.FAILED
            && state != WorkflowInstance.WorkflowState.STOPPED) {
      return Response.status(Status.FORBIDDEN).build();
    }

    try {
      service.cleanupWorkflowInstances(buffer, state);
      return Response.ok().build();
    } catch (WorkflowDatabaseException e) {
      throw new WebApplicationException(e);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.rest.AbstractJobProducerEndpoint#getService()
   */
  @Override
  public JobProducer getService() {
    if (service instanceof JobProducer) {
      return (JobProducer) service;
    } else {
      return null;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.rest.AbstractJobProducerEndpoint#getServiceRegistry()
   */
  @Override
  public ServiceRegistry getServiceRegistry() {
    return serviceRegistry;
  }
}
