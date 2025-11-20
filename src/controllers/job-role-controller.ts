import type { Request, Response } from 'express';
import type { JobApplicationData, JobRole, NewJobRole } from '../models/job-roles.js';
import { api } from '../services/api.js';
import type { JobRoleService } from '../services/job-role-service.js';
import type { JobApplicationValidator } from '../validators/index.js';

export class JobRoleController {
  constructor(
    private readonly jobRoleService: JobRoleService,
    private readonly applicationValidator: JobApplicationValidator
  ) {}

  async getAllJobRoles(req: Request, res: Response): Promise<void> {
    try {
      // Extract filter parameters from query string
      const { name, location, capability, band, sortBy, sortOrder, page, limit } = req.query;

      // Parse pagination parameters
      const pageNumber = page && typeof page === 'string' ? parseInt(page, 10) : 1;

      // Validate and constrain the limit parameter to prevent abuse
      // Users cannot set arbitrary limits via URL manipulation
      const MIN_LIMIT = 5;
      const MAX_LIMIT = 50;
      const DEFAULT_LIMIT = 10;
      let pageLimit = DEFAULT_LIMIT;

      if (limit && typeof limit === 'string') {
        const parsedLimit = parseInt(limit, 10);
        // Ensure limit is a valid number and within acceptable bounds
        if (!Number.isNaN(parsedLimit) && parsedLimit >= MIN_LIMIT && parsedLimit <= MAX_LIMIT) {
          pageLimit = parsedLimit;
        }
      }

      const offset = (pageNumber - 1) * pageLimit;

      // Parse multiple values for checkboxes (location, capability, band can have multiple values)
      const nameFilter = name && typeof name === 'string' ? name : undefined;
      const locationFilters = location
        ? (Array.isArray(location) ? location : [location]).filter(
            (l): l is string => typeof l === 'string'
          )
        : [];
      const capabilityFilters = capability
        ? (Array.isArray(capability) ? capability : [capability]).filter(
            (c): c is string => typeof c === 'string'
          )
        : [];
      const bandFilters = band
        ? (Array.isArray(band) ? band : [band]).filter((b): b is string => typeof b === 'string')
        : [];

      // Extract sorting parameters
      const sortByParam = sortBy && typeof sortBy === 'string' ? sortBy : undefined;
      const sortOrderParam = sortOrder && typeof sortOrder === 'string' ? sortOrder : undefined;

      // Get all job roles for filtering on frontend
      const allJobRoles: JobRole[] = await api.getJobs(sortByParam, sortOrderParam);

      // Apply filters on the frontend side to the full dataset
      let filteredJobs = allJobRoles;

      if (nameFilter) {
        const searchTerm = nameFilter.toLowerCase();
        filteredJobs = filteredJobs.filter((job) => job.name.toLowerCase().includes(searchTerm));
      }

      if (locationFilters.length > 0) {
        filteredJobs = filteredJobs.filter((job) =>
          locationFilters.some((loc) => job.location.toLowerCase() === loc.toLowerCase())
        );
      }

      if (capabilityFilters.length > 0) {
        filteredJobs = filteredJobs.filter((job) =>
          capabilityFilters.some((cap) => job.capability.toLowerCase() === cap.toLowerCase())
        );
      }

      if (bandFilters.length > 0) {
        filteredJobs = filteredJobs.filter((job) =>
          bandFilters.some((b) => job.band.toLowerCase() === b.toLowerCase())
        );
      }

      // Apply pagination to filtered results
      const totalFilteredJobs = filteredJobs.length;
      const paginatedJobs = filteredJobs.slice(offset, offset + pageLimit);

      // Calculate pagination info
      const totalPages = Math.ceil(totalFilteredJobs / pageLimit);
      const hasNextPage = pageNumber < totalPages;
      const hasPrevPage = pageNumber > 1;

      // Get distinct values for filter dropdowns from all jobs
      const distinctValues = await api.getDistinctValues();

      // Keep title consistent regardless of filters
      const title = 'Available Job Roles';

      res.render('job-roles/job-role-list', {
        title,
        jobRoles: paginatedJobs,
        currentFilters: {
          name: nameFilter,
          location: locationFilters,
          capability: capabilityFilters,
          band: bandFilters,
        },
        currentSort: {
          sortBy: sortByParam,
          sortOrder: sortOrderParam,
        },
        pagination: {
          currentPage: pageNumber,
          totalPages,
          limit: pageLimit,
          totalResults: totalFilteredJobs,
          hasNextPage,
          hasPrevPage,
        },
        distinctValues,
      });
    } catch (error) {
      console.error('Error fetching job roles:', error);
      res.status(500).send('Error loading job roles');
    }
  }

  async getJobRoleById(req: Request, res: Response): Promise<void> {
    const { id } = req.params;

    try {
      if (!id) {
        res.status(400).send('Job role ID is required');
        return;
      }

      // Validate that ID is a positive integer
      const numericId = Number.parseInt(id, 10);
      if (Number.isNaN(numericId) || numericId <= 0 || !Number.isInteger(numericId)) {
        res.status(400).send('Invalid job role ID. ID must be a positive integer.');
        return;
      }

      // Fetch job role details directly from the backend API
      const jobRole = await api.getJobById(id);

      res.render('job-roles/detail', {
        title: jobRole.name,
        jobRole,
      });
    } catch (error) {
      console.error('Error fetching job role:', error);
      // Check if it's a 404 error
      if (error instanceof Error && 'response' in error) {
        const axiosError = error as { response?: { status: number } };
        if (axiosError.response?.status === 404) {
          res.status(404).send(`Job role with ID ${id} not found`);
          return;
        }
      }
      res.status(500).send('Error loading job role details');
    }
  }

  async getJobRoleDetails(req: Request, res: Response): Promise<void> {
    const { id } = req.params;
    const { applicationSubmitted, hired, rejected, error } = req.query;

    try {
      if (!id) {
        res.status(400).send('Job role ID is required');
        return;
      }

      // Validate that ID is a positive integer
      const numericId = Number.parseInt(id, 10);
      if (Number.isNaN(numericId) || numericId <= 0 || !Number.isInteger(numericId)) {
        res.status(400).send('Invalid job role ID. ID must be a positive integer.');
        return;
      }

      // Fetch job role details directly from the backend API
      const jobRoleDetails = await api.getJobById(id);

      // If user is admin, also fetch applications for this job role
      let applications: Array<{
        applicationID: number;
        jobRoleId: number;
        phoneNumber: string;
        emailAddress: string;
        status: string;
        coverLetter?: string | null;
        notes?: string | null;
        createdAt: string;
        updatedAt: string;
        applicantName?: string;
        cvUrl?: string;
        userId?: string;
        formattedDate?: string;
        displayName: string;
      }> = [];

      if (req.user?.role === 'admin') {
        try {
          const rawApplications = await api.getJobApplications(id, req.accessToken);
          // Format the dates for display and create display names
          // Filter out rejected applications so they don't appear in the list
          applications = rawApplications
            .filter((app) => app.status !== 'Rejected')
            .map((app) => ({
              ...app,
              formattedDate: new Date(app.createdAt).toLocaleDateString('en-GB', {
                day: '2-digit',
                month: 'short',
                year: 'numeric',
              }),
              displayName: app.applicantName || app.emailAddress.split('@')[0] || 'Unknown User',
            }));
        } catch (applicationError) {
          console.error('Error fetching applications:', applicationError);
          // Don't fail the whole page if applications can't be loaded
        }
      }

      // Check if the user has already applied for this job role (non-admin users only)
      let hasApplied = false;
      if (req.user && req.user.role !== 'admin' && req.user.email) {
        try {
          const userApplications = await api.getMyApplications(req.user.email);
          hasApplied = userApplications.some(
            (app) => app.jobRoleId === numericId && app.status !== 'Withdrawn'
          );
        } catch (applicationError) {
          console.error('Error checking user applications:', applicationError);
          // Don't fail the whole page if checking applications fails
        }
      }

      res.render('job-roles/detail', {
        title: `${jobRoleDetails.name} - Job Details`,
        jobRole: jobRoleDetails,
        applications,
        user: req.user,
        hasApplied,
        applicationSubmitted: applicationSubmitted === 'true',
        hired: hired === 'true',
        rejected: rejected === 'true',
        error: error as string | undefined,
      });
    } catch (error) {
      console.error('Error fetching job role details:', error);
      // Check if it's a 404 error
      if (error instanceof Error && 'response' in error) {
        const axiosError = error as { response?: { status: number } };
        if (axiosError.response?.status === 404) {
          res.status(404).send(`Job role with ID ${id} not found`);
          return;
        }
      }
      res.status(500).send('Error loading job role details');
    }
  }

  async getJobRoleApplication(req: Request, res: Response): Promise<void> {
    const { id } = req.params;

    try {
      if (!id) {
        res.status(400).send('Job role ID is required');
        return;
      }

      // Validate that ID is a positive integer
      const numericId = Number.parseInt(id, 10);
      if (Number.isNaN(numericId) || numericId <= 0 || !Number.isInteger(numericId)) {
        res.status(400).send('Invalid job role ID. ID must be a positive integer.');
        return;
      }

      // Check if the user has already applied for this job role
      if (req.user?.email) {
        try {
          const userApplications = await api.getMyApplications(req.user.email);
          const hasApplied = userApplications.some(
            (app) => app.jobRoleId === numericId && app.status !== 'Withdrawn'
          );

          if (hasApplied) {
            res.redirect(
              `/jobs/${id}/details?error=${encodeURIComponent('You have already applied for this position.')}`
            );
            return;
          }
        } catch (checkError) {
          console.error('Error checking existing applications:', checkError);
          // Continue to show form if check fails
        }
      }

      // Fetch job role details directly from the backend API
      const jobRoleDetails = await api.getJobById(id);

      if (!jobRoleDetails) {
        res.status(404).send(`Job role with ID ${id} not found`);
        return;
      }

      // Render the application form with pre-filled user email
      res.render('job-roles/apply', {
        title: `Apply for ${jobRoleDetails.name}`,
        jobRole: jobRoleDetails,
        userEmail: req.user?.email,
      });
    } catch (error) {
      console.error('Error fetching job role for application:', error);
      // Check if it's a 404 error
      if (error instanceof Error && 'response' in error) {
        const axiosError = error as { response?: { status: number } };
        if (axiosError.response?.status === 404) {
          res.status(404).send(`Job role with ID ${id} not found`);
          return;
        }
      }
      res.status(500).send('Error loading job application page');
    }
  }

  async submitJobRoleApplication(req: Request, res: Response): Promise<void> {
    const { id } = req.params;

    try {
      if (!id) {
        res.status(400).render('error', {
          title: 'Invalid Request',
          message: 'Job role ID is required',
          user: req.user,
        });
        return;
      }

      // Validate that ID is a positive integer
      const numericId = Number.parseInt(id, 10);
      if (Number.isNaN(numericId) || numericId <= 0 || !Number.isInteger(numericId)) {
        res.status(400).render('error', {
          title: 'Invalid Request',
          message: 'Invalid job role ID. Please check the URL and try again.',
          user: req.user,
        });
        return;
      }

      // Get form data
      const applicationData = req.body as JobApplicationData;

      // Validate application data
      const validationResult = this.applicationValidator.validate(applicationData);
      if (!validationResult.isValid) {
        // Fetch job role details to re-render the form with errors
        try {
          const jobRoleDetails = await api.getJobById(id);
          res.status(400).render('job-roles/apply', {
            title: `Apply for ${jobRoleDetails.name}`,
            jobRole: jobRoleDetails,
            user: req.user,
            errors: validationResult.errors,
            formData: applicationData, // Preserve form data
          });
          return;
        } catch (_fetchError) {
          // If we can't fetch the job role, show a generic error page
          res.status(400).render('error', {
            title: 'Validation Error',
            message: `Please fix the following errors: ${validationResult.errors.join('; ')}`,
            user: req.user,
          });
          return;
        }
      }

      // Check if the user has already applied for this job role
      if (req.user?.email) {
        try {
          const userApplications = await api.getMyApplications(req.user.email);
          const hasApplied = userApplications.some(
            (app) => app.jobRoleId === numericId && app.status !== 'Withdrawn'
          );

          if (hasApplied) {
            res.redirect(
              `/jobs/${id}/details?error=${encodeURIComponent('You have already applied for this position.')}`
            );
            return;
          }
        } catch (checkError) {
          console.error('Error checking existing applications:', checkError);
          // Continue with submission if check fails
        }
      }

      // Map frontend form data to backend API format
      // Combine additional information into notes field
      const notes = [
        `Name: ${applicationData.firstName} ${applicationData.lastName}`,
        `Current Job Title: ${applicationData.currentJobTitle}`,
        `Years of Experience: ${applicationData.yearsOfExperience}`,
        applicationData.linkedinUrl ? `LinkedIn: ${applicationData.linkedinUrl}` : '',
        applicationData.additionalComments ? `Comments: ${applicationData.additionalComments}` : '',
        req.file ? `CV: /uploads/${req.file.filename}` : '',
      ]
        .filter((line) => line)
        .join('\n');

      // Submit application to backend API
      const backendApplicationData = {
        jobRoleId: numericId,
        emailAddress: applicationData.email,
        phoneNumber: applicationData.phone,
        coverLetter: applicationData.coverLetter,
        notes: notes,
      };

      const result = await api.submitApplication(backendApplicationData);

      if (result.success) {
        // Redirect to success page with application ID
        res.redirect(
          `/jobs/${id}/details?applicationSubmitted=true&applicationId=${result.applicationID}`
        );
      } else {
        // Re-render the form with the error message and preserved form data
        try {
          const jobRoleDetails = await api.getJobById(id);
          res.status(400).render('job-roles/apply', {
            title: `Apply for ${jobRoleDetails.name}`,
            jobRole: jobRoleDetails,
            user: req.user,
            errors: [result.message || 'Failed to submit application. Please try again.'],
            formData: applicationData,
          });
        } catch (_fetchError) {
          res.status(400).render('error', {
            title: 'Application Submission Failed',
            message: result.message || 'Failed to submit application. Please try again.',
            user: req.user,
          });
        }
      }
    } catch (error) {
      console.error('Error submitting job application:', error);

      // Extract useful error message from axios error if available
      let errorMessage = 'An error occurred while submitting your application. Please try again.';
      if (error && typeof error === 'object' && 'response' in error) {
        const axiosError = error as { response?: { data?: { message?: string } } };
        if (axiosError.response?.data?.message) {
          errorMessage = axiosError.response.data.message;
        }
      }

      // Try to re-render the form with the error, or fall back to error page
      try {
        if (id) {
          const applicationData = req.body as JobApplicationData;
          const jobRoleDetails = await api.getJobById(id);
          res.status(500).render('job-roles/apply', {
            title: `Apply for ${jobRoleDetails.name}`,
            jobRole: jobRoleDetails,
            user: req.user,
            errors: [errorMessage],
            formData: applicationData,
          });
        } else {
          res.status(500).render('error', {
            title: 'Application Error',
            message: errorMessage,
            user: req.user,
          });
        }
      } catch (_renderError) {
        res.status(500).render('error', {
          title: 'Application Error',
          message: errorMessage,
          user: req.user,
        });
      }
    }
  }

  async generateJobRolesReport(_req: Request, res: Response): Promise<void> {
    try {
      const csvContent = await this.jobRoleService.generateJobRolesReportCsv();

      // Set headers for file download
      const timestamp = new Date().toISOString().split('T')[0];
      const filename = `job-roles-report-${timestamp}.csv`;

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.status(200).send(csvContent);
    } catch (error) {
      console.error('Error generating job roles report:', error);
      res.status(500).send('Error generating report');
    }
  }

  async showNewJobRoleForm(_req: Request, res: Response): Promise<void> {
    try {
      const locationOptions = [
        'Belfast',
        'London',
        'Manchester',
        'Birmingham',
        'Edinburgh',
        'Leeds',
        'Glasgow',
        'Remote',
      ];

      // Fetch capabilities, bands, and statuses from the API
      const [capabilities, bands, statuses] = await Promise.all([
        api.getCapabilities(),
        api.getBands(),
        api.getStatuses(),
      ]);

      res.render('job-roles/new', {
        title: 'Add New Job Role',
        locationOptions,
        capabilities,
        bands,
        statuses,
      });
    } catch (error) {
      console.error('Error loading new job role form:', error);
      res.status(500).send('Error loading form');
    }
  }

  async createJobRole(req: Request, res: Response): Promise<void> {
    try {
      const jobRoleData = req.body as NewJobRole;

      // Validate required fields
      if (
        !jobRoleData.name ||
        !jobRoleData.location ||
        !jobRoleData.capabilityId ||
        !jobRoleData.bandId ||
        !jobRoleData.closingDate
      ) {
        res
          .status(400)
          .send(
            'Missing required fields: name, location, capabilityId, bandId, and closingDate are required'
          );
        return;
      }

      // Parse IDs
      const capabilityId = parseInt(jobRoleData.capabilityId, 10);
      const bandId = parseInt(jobRoleData.bandId, 10);
      const statusId = jobRoleData.statusId ? parseInt(jobRoleData.statusId, 10) : undefined;

      if (Number.isNaN(capabilityId) || Number.isNaN(bandId)) {
        res.status(400).send('Invalid capability or band ID');
        return;
      }

      if (statusId !== undefined && Number.isNaN(statusId)) {
        res.status(400).send('Invalid status ID');
        return;
      }

      // Parse openPositions if provided
      let openPositions: number | undefined;
      if (jobRoleData.openPositions) {
        openPositions = parseInt(jobRoleData.openPositions, 10);
        if (Number.isNaN(openPositions) || openPositions < 1) {
          res.status(400).send('Open positions must be a positive number');
          return;
        }
      }

      // Get access token from cookies for backend API authentication
      const accessToken = req.cookies?.['access_token'];

      // Create the job role
      const newJobRole = await this.jobRoleService.createJobRole(
        {
          name: jobRoleData.name.trim(),
          location: jobRoleData.location,
          capabilityId,
          bandId,
          closingDate: new Date(jobRoleData.closingDate),
          description: jobRoleData.description?.trim() || undefined,
          responsibilities: jobRoleData.responsibilities?.trim() || undefined,
          jobSpecUrl: jobRoleData.jobSpecUrl?.trim() || undefined,
          openPositions,
          ...(statusId && { statusId }),
        },
        accessToken
      );

      // Redirect to the new job role details page
      res.redirect(`/jobs/${newJobRole.id}/details`);
    } catch (error) {
      console.error('Error creating job role:', error);
      res.status(500).send('Error creating job role');
    }
  }

  async deleteJobRole(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).send('Job role ID is required');
        return;
      }

      // Validate that ID is a positive integer
      const numericId = Number.parseInt(id, 10);
      if (Number.isNaN(numericId) || numericId <= 0 || !Number.isInteger(numericId)) {
        res.status(400).send('Invalid job role ID. ID must be a positive integer.');
        return;
      }

      // Get access token from cookies for backend API authentication
      const accessToken = req.cookies?.['access_token'];

      const success = await this.jobRoleService.deleteJobRole(id, accessToken);

      if (!success) {
        res.status(404).send(`Job role with ID ${id} not found`);
        return;
      }

      // Redirect to the job list page with a success message
      res.redirect('/jobs?deleted=true');
    } catch (error) {
      console.error('Error deleting job role:', error);
      res.status(500).send('Error deleting job role');
    }
  }

  async showEditJobRoleForm(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).send('Job role ID is required');
        return;
      }

      // Validate that ID is a positive integer
      const numericId = Number.parseInt(id, 10);
      if (Number.isNaN(numericId) || numericId <= 0 || !Number.isInteger(numericId)) {
        res.status(400).send('Invalid job role ID. ID must be a positive integer.');
        return;
      }

      const jobRole = await this.jobRoleService.getJobRoleDetailsById(id);

      if (!jobRole) {
        res.status(404).send(`Job role with ID ${id} not found`);
        return;
      }

      const locationOptions = [
        'Belfast',
        'London',
        'Manchester',
        'Birmingham',
        'Edinburgh',
        'Leeds',
        'Glasgow',
        'Remote',
      ];

      // Fetch capabilities, bands, and statuses from the API
      const [capabilities, bands, statuses] = await Promise.all([
        api.getCapabilities(),
        api.getBands(),
        api.getStatuses(),
      ]);

      // Format responsibilities as string for textarea
      const responsibilitiesText = Array.isArray(jobRole.responsibilities)
        ? jobRole.responsibilities.join('\n')
        : jobRole.responsibilities || '';

      // Format closing date for input field (YYYY-MM-DD)
      const closingDateFormatted = jobRole.closingDate.toISOString().split('T')[0];

      res.render('job-roles/edit', {
        title: `Edit ${jobRole.name}`,
        jobRole: {
          ...jobRole,
          responsibilities: responsibilitiesText,
          closingDate: closingDateFormatted,
        },
        locationOptions,
        capabilities,
        bands,
        statuses,
      });
    } catch (error) {
      console.error('Error loading edit job role form:', error);
      res.status(500).send('Error loading form');
    }
  }

  async updateJobRole(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).send('Job role ID is required');
        return;
      }

      // Validate that ID is a positive integer
      const numericId = Number.parseInt(id, 10);
      if (Number.isNaN(numericId) || numericId <= 0 || !Number.isInteger(numericId)) {
        res.status(400).send('Invalid job role ID. ID must be a positive integer.');
        return;
      }

      const jobRoleData = req.body as NewJobRole;

      // Validate required fields
      if (
        !jobRoleData.name ||
        !jobRoleData.location ||
        !jobRoleData.capabilityId ||
        !jobRoleData.bandId ||
        !jobRoleData.closingDate
      ) {
        res
          .status(400)
          .send(
            'Missing required fields: name, location, capabilityId, bandId, and closingDate are required'
          );
        return;
      }

      // Parse IDs
      const capabilityId = parseInt(jobRoleData.capabilityId, 10);
      const bandId = parseInt(jobRoleData.bandId, 10);

      if (Number.isNaN(capabilityId) || Number.isNaN(bandId)) {
        res.status(400).send('Invalid capability or band ID');
        return;
      }

      // Build update object that matches UpdateJobRoleRequest interface
      const updateData = {
        roleName: jobRoleData.name.trim(),
        location: jobRoleData.location,
        capabilityId,
        bandId,
        closingDate: jobRoleData.closingDate, // Keep as string
      };

      // Add optional fields
      const optionalData: {
        description?: string;
        responsibilities?: string;
        jobSpecUrl?: string;
        openPositions?: number;
        statusId?: number;
      } = {};

      if (jobRoleData.description?.trim()) {
        optionalData.description = jobRoleData.description.trim();
      }
      if (jobRoleData.responsibilities?.trim()) {
        optionalData.responsibilities = jobRoleData.responsibilities.trim();
      }
      if (jobRoleData.jobSpecUrl?.trim()) {
        optionalData.jobSpecUrl = jobRoleData.jobSpecUrl.trim();
      }
      if (jobRoleData.openPositions) {
        optionalData.openPositions = parseInt(jobRoleData.openPositions, 10);
      }
      if (req.body.status) {
        // Convert status text to statusId if needed
        optionalData.statusId = req.body.statusId || undefined;
      }

      // Get access token from cookies for backend API authentication
      const accessToken = req.cookies?.['access_token'];

      // Update the job role
      const updatedJobRole = await this.jobRoleService.updateJobRole(
        id,
        {
          ...updateData,
          ...optionalData,
        },
        accessToken
      );

      if (!updatedJobRole) {
        res.status(404).send(`Job role with ID ${id} not found`);
        return;
      }

      // Redirect to the updated job role details page
      res.redirect(`/jobs/${id}/details`);
    } catch (error) {
      console.error('Error updating job role:', error);
      res.status(500).send('Error updating job role');
    }
  }

  async getMyApplications(req: Request, res: Response): Promise<void> {
    try {
      // Get user email from request
      const userEmail = req.user?.email;

      if (!userEmail) {
        res.redirect('/auth/login');
        return;
      }

      // Fetch user's applications from backend
      const backendApplications = await api.getMyApplications(userEmail);

      // Transform backend response to match template expectations
      const applications = backendApplications.map((app) => {
        // Map backend status to frontend status display
        let applicationStatus: string;
        if (app.status === 'Accepted' || app.status === 'Hired') {
          applicationStatus = 'Hired';
        } else if (app.status === 'Rejected') {
          applicationStatus = 'Rejected';
        } else if (app.status === 'Reviewed') {
          applicationStatus = 'Under Review';
        } else if (app.status === 'Withdrawn') {
          applicationStatus = 'Withdrawn';
        } else {
          applicationStatus = 'In Progress'; // Pending
        }

        return {
          id: app.applicationID,
          jobRoleId: app.jobRoleId,
          roleName: app.jobRoleName || 'Position Not Available',
          location: app.jobRoleLocation || 'Location Not Specified',
          capability: app.capabilityName || 'Not Specified',
          band: app.bandName || 'Not Specified',
          applicationStatus,
          appliedDate: new Date(app.createdAt),
          emailAddress: app.emailAddress,
        };
      });

      // Render the my-applications page
      res.render('job-roles/my-applications', {
        title: 'My Job Applications',
        applications,
        user: req.user,
      });
    } catch (error) {
      console.error('Error fetching user applications:', error);
      res.status(500).render('error', { message: 'Unable to load your applications' });
    }
  }

  async hireApplicant(req: Request, res: Response): Promise<void> {
    const { id: jobRoleId, applicationId } = req.params;

    try {
      if (!jobRoleId || !applicationId) {
        res.status(400).send('Job role ID and application ID are required');
        return;
      }

      // Validate that IDs are positive integers
      const numericJobRoleId = Number.parseInt(jobRoleId, 10);
      const numericApplicationId = Number.parseInt(applicationId, 10);

      if (
        Number.isNaN(numericJobRoleId) ||
        numericJobRoleId <= 0 ||
        !Number.isInteger(numericJobRoleId)
      ) {
        res.status(400).send('Invalid job role ID. ID must be a positive integer.');
        return;
      }

      if (
        Number.isNaN(numericApplicationId) ||
        numericApplicationId <= 0 ||
        !Number.isInteger(numericApplicationId)
      ) {
        res.status(400).send('Invalid application ID. ID must be a positive integer.');
        return;
      }

      const result = await api.hireApplicant(jobRoleId, applicationId, req.accessToken);

      if (result.success) {
        res.redirect(`/jobs/${jobRoleId}/details?hired=true`);
      } else {
        res.redirect(
          `/jobs/${jobRoleId}/details?error=${encodeURIComponent(result.message || 'Failed to hire applicant')}`
        );
      }
    } catch (error) {
      console.error('Error hiring applicant:', error);
      const errorMessage =
        error instanceof Error && 'response' in error
          ? (error as { response?: { data?: { message?: string } } }).response?.data?.message ||
            (error as Error).message
          : 'Error processing hire request';
      res.redirect(`/jobs/${jobRoleId}/details?error=${encodeURIComponent(errorMessage)}`);
    }
  }

  async rejectApplicant(req: Request, res: Response): Promise<void> {
    const { id: jobRoleId, applicationId } = req.params;

    try {
      if (!jobRoleId || !applicationId) {
        res.status(400).send('Job role ID and application ID are required');
        return;
      }

      // Validate that IDs are positive integers
      const numericJobRoleId = Number.parseInt(jobRoleId, 10);
      const numericApplicationId = Number.parseInt(applicationId, 10);

      if (
        Number.isNaN(numericJobRoleId) ||
        numericJobRoleId <= 0 ||
        !Number.isInteger(numericJobRoleId)
      ) {
        res.status(400).send('Invalid job role ID. ID must be a positive integer.');
        return;
      }

      if (
        Number.isNaN(numericApplicationId) ||
        numericApplicationId <= 0 ||
        !Number.isInteger(numericApplicationId)
      ) {
        res.status(400).send('Invalid application ID. ID must be a positive integer.');
        return;
      }

      const result = await api.rejectApplicant(jobRoleId, applicationId, req.accessToken);

      if (result.success) {
        res.redirect(`/jobs/${jobRoleId}/details?rejected=true`);
      } else {
        res.status(400).send(result.message || 'Failed to reject applicant');
      }
    } catch (error) {
      console.error('Error rejecting applicant:', error);
      res.status(500).send('Error processing reject request');
    }
  }

  async withdrawApplication(req: Request, res: Response): Promise<void> {
    const { applicationId } = req.params;

    try {
      if (!applicationId) {
        res.status(400).send('Application ID is required');
        return;
      }

      // Check if user is authenticated
      if (!req.user || !req.user.email) {
        res.status(401).send('You must be logged in to withdraw an application');
        return;
      }

      // Validate that application ID is a positive integer
      const numericApplicationId = Number.parseInt(applicationId, 10);

      if (
        Number.isNaN(numericApplicationId) ||
        numericApplicationId <= 0 ||
        !Number.isInteger(numericApplicationId)
      ) {
        res.status(400).send('Invalid application ID. ID must be a positive integer.');
        return;
      }

      // Get access token from cookies to authenticate with backend
      const accessToken = req.cookies?.['access_token'];

      if (!accessToken) {
        console.error('No access token found in cookies');
        res.status(401).send('Authentication token not found. Please log in again.');
        return;
      }

      const result = await api.withdrawApplication(applicationId, accessToken);

      if (result.success) {
        res.redirect('/my-applications?withdrawn=true');
      } else {
        res.status(400).send(result.message || 'Failed to withdraw application');
      }
    } catch (error) {
      console.error('Error withdrawing application:', error);
      if (error instanceof Error) {
        console.error('Error details:', error.message);
      }
      res.status(500).send('Error processing withdraw request');
    }
  }
}
