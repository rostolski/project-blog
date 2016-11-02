

var topSkills = ["Project Management", "Agile/Kanban", "Business Analysis"];
// not using var skills, left in as I might use to create a new section at a later point displaying a larger list of skills
var skills = ["SharePoint", "Team Foundation Server", "SalesForce",
    "VersionOne", "JIRA", "Confluence", "Microsoft Office Suite",
    "Microsoft Project", "Microsoft Outlook", "Microsoft Visio",
    "Agile/Kanban", "Business Analysis", "Project Management",
    "Process Improvement", "Customer Relationship Management",
    "Change Management", "Six Sigma", "Resource and Capacity Planning",
    "HTML", "CSS", "Python", "JavaScript"
];

var overview = "Innovative and experienced project/program manager with a record of " +
    "developing and supporting successful solutions incorporating a wide " +
    "range of applications and technologies.  Currently looking for a new role while "+
    "learning new development skills that led to the creation of this site.";

var bio = {
    "name": "Ryan Ostolski",
    "role": "IT Project Manager",
    "contacts": {
        "mobile": "404-290-2231",
        "email": "ryanostolski@gmail.com",
        "github": "rostolski",
        "location": "Atlanta, GA"
    },
    "overview": overview,
    "skills": topSkills,
    "biopic": "files/fry.jpg"
};

bio.display = function() {
  // displays bio details in index.html
  var formattedWelcome = HTMLwelcomeMsg.replace("%data%", bio.overview);
  $("#header").append(formattedWelcome);

  if (bio.skills.length > 0) {
      $("#header").append(HTMLskillsStart);
      var formattedSkill = HTMLskills.replace("%data%", bio.skills[0]);
      //sets up the skills section and appends the first skill to the page
      $("#header").append(formattedSkill);
      for (i = 1; i < bio.skills.length; i++) {
          //adds the remaining skills to the page
          formattedSkill = HTMLskills.replace("%data%", bio.skills[i]);
          $("#header").append(formattedSkill);
      }
  }

  var formattedName = HTMLheaderName.replace("%data%", bio.name);
  var formattedRole = HTMLheaderRole.replace("%data%", bio.role);
  //var formattedBioPic = HTMLbioPic.replace("%data%", bio.biopic);
  $("#header").prepend(formattedName, formattedRole);


  var formattedMobile = HTMLmobile.replace("%data%", bio.contacts.mobile);
  var formattedEmail = HTMLemail.replace("%data%", bio.contacts.email);
  var formattedAddress = HTMLlocation.replace("%data%", bio.contacts.location);
  var formattedGitHub = HTMLgithub.replace("%data%", bio.contacts.github);

  $("#topContacts").append(formattedMobile, formattedEmail, formattedAddress, formattedGitHub);
  $("#footerContacts").append(formattedMobile, formattedEmail, formattedAddress, formattedGitHub);
};

bio.display();


var work = {
    // defining work object
    "jobs": [{
        "employer": "Core Security",
        "url": "https://www.coresecurity.com",
        "title": "Professional Services Project Manager",
        "dates": "March 2015 - June 2016",
        "location": "Roswell, GA",
        "description": "Actively managed 20-30 consulting engagements with individual budgets ranging from " +
            "20k to 500k lasting 2 weeks-12 months, with each project at various stages to implement IAM & vulnerability " +
            "solutions for customers in several different industries." + "<br>" +
            "•	Led a custom POC initiative delivering integrated functionality between two previously unrelated Core Security " +
            "products with a 3rd party tool (splunk) directly in an early adopting customer’s environment." + "<br>" +
            "•	Introduced new agile process/tools to the Professional Services organization to expedite the implementation of " +
            "Core Security products to customers on time and on budget." + "<br>" +
            "•	Continuously developed a backlog of new requirements during and after customer engagements to directly introduce " +
            "change requests to implement the additional scope requested or for the Sales team to follow up later as future revenue " +
            "generating opportunities." + "<br>" +
            "•	Represented the company on a TAG Young Professionals panel discussing Project Management."

    }, {
        "employer": "Aptean",
        "url": "http://www.aptean.com",
        "title": "Portfolio Project Manager",
        "dates": "Sept 2013 - Jan 2015",
        "location": "Atlanta, GA",
        "description": "Introduced effective PMO practices for the R&D organization to establish common processes " +
            "across all newly integrated product lines.  Continuously drove performance improvements to reduce downtime and " +
            "increase productivity across the organization." + "<br>" +
            "•	Led 2014 portfolio planning including 200+ marketable features across 10 product lines developed within 50+ projects over " +
            "the course of the year." + "<br>" +
            "•	Persistently tracked portfolio status through establishing common reporting methodologies across all projects summarizing " +
            "information in a high level and detailed weekly leadership report out to R&D and Product Management SVPs." + "<br>" +
            "•	Implemented new resource allocation strategies to align R&D resources by knowledge type instead of product type to streamline " +
            "movement of resources between high priority company projects." + "<br>" +
            "•	Effectively coached team Project Managers on team processes and PMO methodologies."

    }, {
        "employer": "Rideout",
        "url" : "http://www.ryanostolski.com/index.html",
        "title": "Co-Founder",
        "dates": "Jan 2014 - July 2014",
        "location": "Atlanta, GA",
        "description": "Brought a mobile application from concept to prototype.  Using the prototype we successfully completed a soft launch " +
            "providing potential investors with the market potential of a fully developed application.  We were unable to secure additional financing " +
            "to bring the application to the next stage and closed the company." + "<br>" +
            "•	Developed application design and story boards then through consulting with offshore development teams developed an initial mobile " +
            "application, backend database and company website." + "<br>" +
            "•	Soft launched the mobile application with 300+ registered customers and service providers." + "<br>" +
            "•	Created Business Plan and next steps to move from prototype to fully developed application." + "<br>" +
            "•	Engage multiple investment groups for additional funding and advisement including groups of disenfranchised service providers of a " +
            "major competitor, Atlanta Tech Village and ATDC."

    }, {
        "employer": "InterCall",
        "url": "http://www.intercall.com",
        "title": "Technical Project Manager",
        "dates": "Jan 2013 - Sept 2013",
        "location": "Atlanta, GA",
        "description": "Oversaw development and implementation of a custom CRM software solution to support core company telecommunications and web " +
            "conferencing products at multiple call center locations. Drove performance of team of 25, supporting project management processes, documenting " +
            "agile project management, while administrating Jira/Confluence for other project teams to utilize. Administered budget of $8M annually, with " +
            "ROI of $15M." + "<br>" +
            "•	Effectively increased user adoption implementing a new escalation process to expedite the development and implementation" +
            " of critical CRM components." + "<br>" +
            "•	Created agile training material and coached project managers through agile processes to prepare them to implement " +
            "Agile within their project teams." + "<br>" +
            "•	Decreased the new enhancement process from a three-year wait to a one-month turnaround on initial delivery of some functionality." + "<br>" +
            "•	Enhanced efficiencies in filtering user feedback into the right channel, issue, question and enhancement."

    }, {
        "employer": "GE Energy",
        "url": "http://www.ge.com",
        "title": "Multiple Project/Implementation Manager roles",
        "dates": "June 2010 - Oct 2012",
        "location": "Multiple Cities",
        "description": "<b>ERP Implementation Leader</b> Managed PMO IT Projects for an Oracle ERP Implementation, leading the conversions of Purchase " +
            "Order and Project data sources. Introduced change management to minimize customizations to the ERP." + "<br>" +
            "<b>Engineering Tools Leader</b> Managed Engineering tools for Digital Energy engineering, developing new system upgrade processes while partnering " +
            "with Corporate IT teams. Collaborated with Application Support to support existing company applications under information technology control." + "<br>" +
            "<b>Collaboration Tools Integration Leader</b> Managed Collaboration Tools segment of an acquisition integration bringing the new Power Conversion " +
            "business unit (previously known as Converteam) of 5,500 employees into GE Energy." + "<br>" +
            "<b>IT Project Manager</b> Managed Functional ID Project within the IT Governance group, implemented Quality Center 10 while leading the system " +
            "integration and user acceptance testing. Trained users on all Functional ID enhancements to the Identity Management System, implemented " +
            "process improvements for over 30 Oracle ERP applications." + "<br>" +
            "<b>Repairs SAP Operations Implementation Leader</b> Managed Phase 1 Project Activities, leading user acceptance testing and training during " +
            "phase 2 system integration testing to identify shop advocates to later increase user adoption rates. Trained multiple new SAP Operation " +
            "Leaders through the Repairs SAP application."
    }, {
        "employer": "The Home Depot",
        "url": "http://www.homedepot.com",
        "title": "Systems Engineer",
        "dates": "May 2007 - June 2010",
        "location": "Atlanta, GA",
        "description": "Managed non-production store environments for numerous technical projects, leading initiation through to production release " +
            "to over 2,000 store environments. Drove operations of 18 quality assurance laboratory environments in 3 countries, managing teams of " +
            "offsite contractors in Canada and India. Developed database to track and plan the allocation of resources."
    }]
};


work.display = function() {
  // displays work details in index.html
  work.jobs.forEach(function(job) {
      $("#workExperience").append(HTMLworkStart);
      var formattedWorkEmployer = HTMLworkEmployer.replace("%data%", job.employer).replace("#", job.url);
      var formattedWorkDates = HTMLworkDates.replace("%data%", job.dates);
      // Trying to get formattedWorkDates on the same line as formattedWorkEmployer - couldnt get that to work

      var formattedWorkTitle = HTMLworkTitle.replace("%data%", job.title);
      var formattedWorkLocation = HTMLworkLocation.replace("%data%", job.location);
      var formattedWorkDescription = HTMLworkDescription.replace("%data%", job.description);
      var formattedMap = googleMap.replace("map", job.location);
      $(".map:last").append(formattedMap);
      $(".work-entry:last").append(formattedWorkEmployer+formattedWorkDates, formattedWorkTitle+formattedWorkLocation, formattedWorkDescription);
  });

};

work.display();

var education = {
    "schools": [{
        "name": "University of Georgia",
        "location": "Athens, GA",
        "degree": "Masters",
        "majors": "MBA",
        "dates": "2009 - 2011",
        "url": "http://www.uga.edu"
    }, {
        "name": "Georgia College & State University",
        "location": "Milledgeville, GA",
        "degree": "Bachelors",
        "majors": "MIS",
        "dates": "2003 - 2007",
        "url": "http://www.gcsu.edu"
    }],
    "certifications": [{
        "title": "Project Management Professional (PMP)",
        "organization": "Project Mangement Institute",
        "dates": "Issued: June 2016 - Expires: June 2019",
        "documentation": "files/PMP.pdf"
    }, {
        "title": "Certified Scrum Master (CSM)",
        "organization": "Scrum Alliance",
        "dates": "Issued: September 2016 - Expires: September 2018",
        "documentation": "files/CSM.pdf"
    }],
    "onlineCourses": [{
        "title": "Intro to Programming NanoDegree",
        "school": "Udacity",
        "dates": "Finished October 2016",
        "url": "files/IntroNanoDegree.pdf"
    }, {
        "title": "Full Stack Web Developer NanoDegree - In Progress",
        "school": "Udacity",
        "dates": "Started October 2016",
        "url": "https://www.udacity.com/course/full-stack-web-developer-nanodegree--nd004"
    }
  ]
};


education.display = function(){
  // displays education details in index.html
  // seperate statements created for schools, certifications and onlineCourses

  education.schools.forEach(function(school) {
      $("#education").append(HTMLschoolStart);
      var formattedSchoolName = HTMLschoolName.replace("%data%", school.name).replace("#", school.url);
      var formattedSchoolDegree = HTMLschoolDegree.replace("%data%", school.degree);
      var formattedSchoolDates = HTMLschoolDates.replace("%data%", school.dates);
      var formattedSchoolLocation = HTMLschoolLocation.replace("%data%", school.location);
      var formattedSchoolMajor = HTMLschoolMajor.replace("%data%", school.majors);

      $(".education-entry:last").append(formattedSchoolName+formattedSchoolDegree, formattedSchoolDates, formattedSchoolLocation, formattedSchoolMajor);
  });

  $("#education").append(HTMLcertifications);
  education.certifications.forEach(function(certification) {
      $("#education").append(HTMLschoolStart);
      var formattedCertificationTitle = HTMLonlineTitle.replace("%data%", certification.title).replace("#", certification.documentation);
      var formattedCertificationOrg = HTMLonlineSchool.replace("%data%", certification.organization);
      var formattedCertificationDates = HTMLonlineDates.replace("%data%", certification.dates);
      $(".education-entry:last").append(formattedCertificationTitle+formattedCertificationOrg, formattedCertificationDates, "<br>");
  });

  $("#education").append(HTMLonlineClasses);
  education.onlineCourses.forEach(function(online) {
      $("#education").append(HTMLschoolStart);
      var formattedOnlineTitle = HTMLonlineTitle.replace("%data%", online.title).replace("#", online.url);
      var formattedOnlineSchool = HTMLonlineSchool.replace("%data%", online.school);
      var formattedOnlineDates = HTMLonlineDates.replace("%data%", online.dates);
      $(".education-entry:last").append(formattedOnlineTitle+formattedOnlineSchool, formattedOnlineDates, "<br>");
  });



};

education.display();

var images = [["files/Fresh-Tomatoes-Site.jpg", "files/Movie-Code.jpg"],["files/gcp.jpg"]];
var imageTitle = [["Python Generated HTML Site", "Code snapshot"],["Google Cloud Platform"]];
var imageDescription = [["",""],[""]];

var projects = {
    "projects": [{
        "title": "Movie Website",
        "dates": "September 2016",
        "description": "This was a project as a part of the Intro to Programming NanoDegree " +
            "utilizing Python to generate an html page.  That generated HTML page is displayed if you click " +
            "on the Movie Website header.  On the Movie Website, upon clicking on an image a trailer will play for that " +
            "movie.",
        "images": images[0],
        "imageTitle" : imageTitle[0],
        "imageDescription" : imageDescription[0],
        "fileLink" : "movie_website/fresh_tomatoes.html"
    },
    {
        "title": "Full Stack Blog",
        "dates": "November 2016",
        "description": "Within the Full Stack Nano Degee one of the projects was the creation of a " +
              "blog portal.  Within that portal includes the ability to create a new account, sign in/out " +
              "and while signed in create new postings, like other's posts or comment on previous posts.  With " +
              "the blog now finished, anyone can access it by clicking on Ful Stack Blog above and creating an account.  " +
              "User/Password information will be hashed and stored in a cookie for when you come back to the site.",
        "images": images[1],
        "imageTitle" : imageTitle[1],
        "imageDescription" : imageDescription[1],
        "fileLink" : "/blog"
    }
  ]
};
id = 0

projects.display = function() {
  // displays project details in index.html
  projects.projects.forEach(function(project) {
      $("#projects").append(HTMLprojectStart);

      var formattedProjectTitle = HTMLprojectTitle.replace("%data%", project.title).replace("#", project.fileLink);
      var formattedProjectDates = HTMLprojectDates.replace("%data%", project.dates);
      var formattedProjectDesc = HTMLprojectDescription.replace("%data%", project.description);
      if (project.images.length > 0) {
          for (i = 0; i < project.images.length; i++) {
              //if there are more than 1 images to add it starts adding 1 image at a time to the project
              formattedProjectImages = HTMLprojectImage.replace("%data%", project.images[i]).replace("%num%", id);
              $(".project-entry:last").append(formattedProjectImages);
              formattedImageExpand = HTMLprojectImageExpand.replace("%num%", id).replace("%title%", project.imageTitle[i]).replace("%image%", project.images[i]).replace("%description%", project.imageDescription[i]);
              $("#imagepop").append(formattedImageExpand);
              id = id + 1
          }
      }
      $(".project-entry:last").prepend(formattedProjectTitle, formattedProjectDates, formattedProjectDesc);
  });

};

projects.display();


//$("main").append(internationalizeButton);

//$("#mapDiv").append(googleMap);


$(document).click(function(loc) {
    var x = loc.pageX;
    var y = loc.pageY;

    logClicks(x, y);
});
