// Global variables
let NODES = {}
let PROPERTIES = {}
const MONTHES = [ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Dec" ]
const DAYS = [ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" ]

// Configure the global variables and display the nodes
$(document).ready(function () {
    // Set today as the default date value of the reservation beginning date
    let now = new Date()
    let dateStr = now.toJSON().split("T")[0];
    let hourStr = now.getHours();
    let minuteStr = now.getMinutes();
    $('#start-date').val(dateStr);
    $('#start-hours').val(hourStr);
    $('#start-minutes').val(minuteStr);
    // Compute the node property list used to create filters
    $.ajax({
        type: "GET",
        url: WEBUI + "/user/node/list",
        dataType: 'json',
        success: function (data) {
            NODES = data["nodes"];
            for (let node in NODES) {
                // Get the properties with values to build the filters
                for (let prop in NODES[node]) {
                    if(NODES[node][prop] != null && String(NODES[node][prop]).length > 0) {
                        if(!(prop in PROPERTIES)) {
                            PROPERTIES[prop] = new Set();
                        }
                        PROPERTIES[prop].add(NODES[node][prop]);
                    } else {
                        // Delete unused properties
                        delete NODES[node][prop];
                    }
                }
            }
            // Sort the properties
            for (let prop of Array.from(Object.keys(PROPERTIES)).sort()) {
                // Add the property name to the selector
                $("#prop-names").append($("<option value='" + prop + "'>"));
            }
        },
        error: function () {
            console.log("error: can not send the request");
        }
    });
    // Set default values
    filterNodes();
    updateNodeSchedule();
    // Update the state every 60s
    setInterval(updateNodeSchedule, 60000);
});

// Functions
function convertHour(hourInt) {
    let result = hourInt;
    if(hourInt > 23) {
        result = hourInt - 24;
    }
    if(hourInt < 0) {
        result = hourInt + 24;
    }
    return String(result).padStart(2, "0");
}

// hoursAdded must be 48 (next two days) or -48 (previous 2 days)
function updateNodeSchedule(hoursAdded=0) {
    // Compute the date of the 2 days to display
    let d1 = $("#d1");
    let d1Html = d1.html().replace(/\s/g, "");
    let firstDayStart;
    if(d1Html.length == 0) {
        hoursAdded = 48;
        // Display the reserved dates from today
        firstDayStart = new Date();
    } else {
        // Display the reserved dates from the next two days
        firstDayStart = new Date($("#d1").html() + " 00:00:00 GMT");
        firstDayStart.setHours(firstDayStart.getHours() + hoursAdded);
    }
    let secondDayStart = new Date(firstDayStart);
    secondDayStart.setHours(secondDayStart.getHours() + 24);
    // Display the dates
    d1.html(DAYS[firstDayStart.getDay()] + " " + firstDayStart.getDate() + " " + MONTHES[firstDayStart.getMonth()] + " " + firstDayStart.getFullYear());
    $("#d2").html(DAYS[secondDayStart.getDay()] + " " + secondDayStart.getDate() + " " + MONTHES[secondDayStart.getMonth()] + " " + secondDayStart.getFullYear());
    // Set the dates to represent the period to display
    // Midnight the first day
    firstDayStart.setHours(0);
    firstDayStart.setMinutes(0);
    firstDayStart.setSeconds(0);
    firstDayStart.setMilliseconds(0);
    // Midnight the second day
    secondDayStart.setHours(0);
    secondDayStart.setMinutes(0);
    secondDayStart.setSeconds(0);
    secondDayStart.setMilliseconds(0);
    // Midnight the day after the second day
    let secondDayEnd = new Date(secondDayStart)
    secondDayEnd.setHours(24);
    secondDayEnd.setMinutes(0);
    secondDayEnd.setSeconds(0);
    secondDayEnd.setMilliseconds(0);
    // Mark the reserved hours in red
    $.ajax({
        type: "GET",
        url: WEBUI + "/user/node/schedule",
        dataType: 'json',
        success: function (data) {
            // Reset the schedule
            $(".one-hour").attr("class", "one-hour free");
            $(".one-hour").each(function(idx, div) {
                if(div.title.includes("reserved")) {
                    let firstLine = div.title.split("\n")[0];
                    div.title = firstLine.replace("reserved", "free");
                }
                if(div.title.includes("now")) {
                    let firstLine = div.title.split("\n")[0];
                    div.title = firstLine;
                }
            });
            // Colour the hour divs to indicate the current hour
            let now = new Date();
            if(now.getTime() < secondDayEnd.getTime() && now.getTime() >= firstDayStart.getTime()) {
                $(".schedule").each(function(idx, div) {
                    let targetDiv = $(div).find(".one-hour:nth-child(" + (now.getHours() + 1) + ")").first();
                    targetDiv.attr("class", "one-hour now").attr("title", targetDiv.attr("title") + "\nnow");
                });
            }
            // Data processing: mark the reserved hours in red
            data = data["nodes"];
            for (let node in data) {
                for (timestamp in data[node]) {
                    let targetTS = parseInt(timestamp) * 1000;
                    // Display the reserved nodes during the first day
                    if(targetTS < secondDayStart.getTime() && targetTS >= firstDayStart.getTime()) {
                        let targetDate = new Date(targetTS);
                        let hourDiv = $("#" + node + "-d1hour" + targetDate.getHours());
                        hourDiv.attr("class", "one-hour reserved");
                        if(hourDiv.attr("title").includes("free")) {
                            hourDiv.attr("title", hourDiv.attr("title").replace("free", "reserved") + "\n" +
                                data[node][timestamp]["owner"] + "\n" +
                                new Date(data[node][timestamp]["start_hour"] * 1000).toTimeString().substring(0,5) + " - " +
                                new Date(data[node][timestamp]["end_hour"] * 1000).toTimeString().substring(0,5));
                        }
                    }
                    // Display the reserved nodes during the second day
                    if(targetTS < secondDayEnd.getTime() && targetTS >= secondDayStart.getTime()) {
                        let targetDate = new Date(targetTS);
                        let hourDiv = $("#" + node + "-d2hour" + targetDate.getHours());
                        hourDiv.attr("class", "one-hour reserved");
                        if(hourDiv.attr("title").includes("free")) {
                            hourDiv.attr("title", hourDiv.attr("title").replace("free", "reserved") + "\n" +
                                data[node][timestamp]["owner"] + "\n" +
                                new Date(data[node][timestamp]["start_hour"] * 1000).toTimeString().substring(0,5) + " - " +
                                new Date(data[node][timestamp]["end_hour"] * 1000).toTimeString().substring(0,5));
                        }
                    }
                }
            }
        },
        error: function() {
            console.log("error: can not send the request");
        }
    });
}

function showInfoView(nodeName) {
    $("#info-node").empty();
    for (let prop in NODES[nodeName]) {
        $("#info-node").append($("<div class='info-prop'>" + prop + ": " + NODES[nodeName][prop] + "</div>"));
    }
    $(".info-view").fadeIn(200);
    event.stopPropagation();
}

function hideInfoView() {
    $(".info-view").fadeOut(400);
}

function displayPropValues() {
    if($("#prop-names-list").val().length > 0) {
        $("#prop-values").empty();
        for (let value of PROPERTIES[$("#prop-names-list").val()]) {
            $("#prop-values").append($("<option value='" + value + "'>"));
        }
    }
}

function addFilter() {
    let filterName = $("#prop-names-list").val();
    let filterValue = $("#prop-values-list").val();
    if(filterName.length > 0 && filterValue.length > 0) {
        let filter = $("<div class='filter'></div>");
        let filterProp = $("<div></div>");
        filterProp.append($("<span>" + filterName + "</span><br/>"));
        filterProp.append($("<span>" + filterValue + "</span>"));
        filter.append(filterProp);
        filter.append($("<div class='suppr' onclick='deleteFilter(this)'>&#x2212;</div>"));
        $(".filters").append(filter);
    }
    $("#prop-names-list").val("");
    $("#prop-values-list").val("");
    filterNodes();
}

function deleteFilter(supprButton) {
    $(supprButton).parent().remove();
    filterNodes();
}

function filterNodes() {
    let filtersHTML = $(".filters .filter div:first-child");
    let filters = {}
    let nb_nodes = 0;
    if(filtersHTML.length > 0) {
        filtersHTML.each(function(idx, div) {
            spans = $(div).children("span").toArray();
            filters[spans[0].innerHTML] = spans[1].innerHTML;
        });
        for (let node in NODES) {
            // Hide the nodes with wrong value for the property 'name'
            let hideNode = false;
            for (let name in filters) {
                if( !(name in NODES[node]) || NODES[node][name] != filters[name]) {
                    hideNode = true;
                }
            }
            if(hideNode) {
                $("#" + node).parent().hide();
            } else {
                $("#" + node).parent().show();
                nb_nodes++;
            }
        }
    } else {
        $(".node-schedule").show();
        $(".node-schedule").each(function() {
            nb_nodes++;
        });
    }
    $(".fuzzy input").val("1");
    $("#nb_print").html("1");
    $(".fuzzy input").attr({ "max": nb_nodes});
    $("#max-number").html(nb_nodes);
}

function updateNbPrint(inputField) {
    $("#nb_print").html($(inputField).val());
}

function addFilterSelection() {
    let filtersHTML = $(".filters .filter div:first-child");
    let filter = $("<div class='filter'></div>");
    let filterProp = $("<div></div>");
    let nodeItems = $(".nodeitems").children();
    if(nodeItems.length == 0) {
        alert("Wrong filter! No selected node.");
        return;
    }
    filtersHTML.each(function(idx, div) {
        // Spans containing the properties to append to the filter selection
        let spans = $(div).children("span").toArray();
        let span = $("<span>" + spans[0].innerHTML + ": " + spans[1].innerHTML + "</span>");
        if(idx > 0) {
            // Show only the first property
            span.hide();
        }
        filterProp.append(span);
    });
    // Append the type of the first displayed node to the selection filter
    let nodeName = $(".node-name:visible").first().children("span").html();
    let span = $("<span>type: " + NODES[nodeName]["type"] + "</span>");
    if(filterProp.children().length > 0) {
      span.hide();
    }
    filterProp.append(span);
    // Add the delete button
    filterProp.append($("<br/>"));
    filterProp.append($("<span>" + $(".fuzzy input").val() + " node(s)</span>"));
    filter.append(filterProp);
    filter.append($("<div class='suppr' onclick='deleteFilter(this)'>&#x2212;</div>"));
    $(".selectednodes .ready-nodes").append(filter);
    // Remove all filters
    $(".filters").empty();
    filterNodes();
}

function addNameFilter(node) {
    let nodeName = $(node).children("span").html();
    let filter = $("<div class='filter'></div>");
    let filterProp = $("<div></div>");
    filterProp.append($("<span>name: " + nodeName + "</span>"));
    let typeSpan = $("<span>agent: " + NODES[nodeName]["agent"] + "</span>");
    typeSpan.hide();
    filterProp.append(typeSpan);
    filterProp.append($("<br/>"));
    filterProp.append($("<span>1 node(s)</span>"));
    filter.append(filterProp);
    filter.append($("<div class='suppr' onclick='deleteFilter(this)'>&#x2212;</div>"));
    $(".selectednodes .ready-nodes").append(filter);
}

function reserveNodes() {
    let filters = []
    if($(".selectednodes .ready-nodes").children().length > 0) {
        // Build the beginning date
        let startDate = new Date($("#start-date").val());
        startDate.setHours($("#start-hours").val());
        startDate.setMinutes($("#start-minutes").val());
        let startDateTS = startDate.getTime();
        // Today, 15 minutes earlier
        if(startDateTS < Date.now() - 15 * 60000) {
            alert("The beginning date is expired. Do not laugh at me!");
            return;
        }
        let duration = parseInt($("#duration").val());
        if(duration > 72) {
            alert("The maximum duration for a reservation is 72 hours");
            return;
        }
        // Total number of requested nodes
        let total_requested = 0;
        // Iterate over .filter elements to add the nodes to the reservation
        $(".selectednodes .ready-nodes").children().each(function() {
            // Read the span tags to get the filter information
            $(this).children().each(function(idx, spanContainer) {
                if(idx == 0) {
                    // Iterate over the span tags to build the filter
                    let spanArray = $(spanContainer).children("span").toArray();
                    let nb_nodes = parseInt(spanArray.pop().innerHTML.split(' ')[0]);
                    let filter = { "nb_nodes": nb_nodes };
                    total_requested += nb_nodes;
                    for (let span of spanArray) {
                        let prop = span.innerHTML.replace(" ", "")
                        let prop_name = prop.split(":")[0]
                        let prop_value = prop.substring(prop.indexOf(":") + 1)
                        filter[prop_name] = prop_value;
                    }
                    filters.push(filter);
                }
            });
        });
        $.ajax({
            type: "POST",
            //the url where you want to sent the userName and password to
            url: WEBUI + "/user/make/reserve",
            dataType: 'json',
            contentType: 'application/json',
            async: false,
            data: JSON.stringify({
                "filters": filters,
                "start_date": Math.floor(startDateTS / 1000),
                "duration": duration
            }),
            success: function (data) {
                msg = ""
                if(data["errors"].length > 0) {
                    msg = "Error:" + data["errors"] + "\n";
                }
                if(data["total_nodes"] == 0) {
                    alert(msg + "The requested nodes are not available on this period!");
                } else {
                    if(data["total_nodes"] < total_requested) {
                        alert("Some nodes are missing.\nConfigure the reserved nodes or cancel your reservation!");
                    }
                    window.location.href = WEBUI + "/user/configure";
                }
            },
            error: function () {
                alert("Error: can not send the request");
            },
        });
    } else {
        alert("Please select nodes before start the deployment");
    }
}
