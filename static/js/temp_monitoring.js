const MONTH_STR = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Now", "Dec" ];

$(document).ready(function () {
    $.ajax({
        type: "GET",
        url: WEBUI + "/user/tempmonitoring/data",
        dataType: 'json',
        success: function (data) {
            for (agent in data) {
                let option = document.createElement("option");
                option.value = agent;
                option.text = agent;
                document.getElementById("agent-list").append(option);
                // Chart colors (https://mokole.com/palette.html)
                let colors = [ "darkslategray", "darkmagenta", "deepskyblue", "pink",
                    "saddlebrown", "maroon3", "blue", "darkgreen", "red", "coral", "olive",
                    "orange", "fuchsia", "darkslateblue", "yellow", "dodgerblue",
                    "mediumseagreen", "lawngreen", "palegoldenrod", "navy", "blueviolet",
                    "powderblue", "yellowgreen", "springgreen", "deeppink", "crimson",
                    "aqua", "violet" ];
                // Looking for the largest set of times
                let max_length = 0;
                let max_values = undefined;
                for (node in data[agent]) {
                    if(data[agent][node]["consumptions"].length > max_length) {
                        max_values = data[agent][node]["consumptions"];
                        max_length = max_values.length;
                    }
                }
                // Configure the charts
                let label_values = [];
                let datasets_values = [];
                // Create the list of labels
                for(cons of max_values) {
                    label_values.push(timestamp2string(cons.time));
                }
                for (node in data[agent]) {
                    let one_dataset = {
                        label: node,
                        data: [],
                        fill: false
                    };
                    let node_cons = data[agent][node];
                    let nonZero = false;
                    for (cons of node_cons["consumptions"]) {
                        if(cons["consumption"] > 0) {
                            nonZero = true;
                        }
                        one_dataset.data.push({
                            x: timestamp2string(cons.time),
                            y: cons.consumption
                        });
                    }
                    // Add to the chart only ports with non-zero consumption
                    if(nonZero) {
                        one_dataset.borderColor = 
                            colors[datasets_values.length % colors.length];
                        datasets_values.push(one_dataset);
                    }
                }
                // Build the chart
                let chartDiv = document.createElement("div");
                chartDiv.style.width = "900px";
                chartDiv.id = agent + "_chart";
                chartDiv.className = "m-auto";
                let canvas = document.createElement("canvas");
                canvas.id = agent + "_canvas";
                chartDiv.append(canvas);
                document.getElementById("charts").append(chartDiv);
                // Configure the canvas
                canvas.style.border  = "1px solid";
                let ctx = document.getElementById(canvas.id).getContext('2d');
                // Add the consumptions
                let myChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: label_values,
                        datasets: datasets_values
                    },
                    options: {
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        },
                        plugins: {
                            legend: {
                                onClick: function(event, elem) {
                                    // Change the default behavior of the
                                    // click on the text of the legend
                                    let allVisible = true;
                                    let showAll = false;
                                    for(ds of myChart.data.datasets) {
                                        allVisible &= !ds.hidden;
                                    }
                                    if(allVisible) {
                                        for(ds of myChart.data.datasets) {
                                            if(ds.label != elem.text) {
                                                ds.hidden = true;
                                            }
                                        }
                                    } else {
                                        for(ds of myChart.data.datasets) {
                                            if(ds.label == elem.text) {
                                                if(ds.hidden) {
                                                    ds.hidden = false;
                                                } else {
                                                    showAll = true;
                                                }
                                            }
                                        }
                                        if(showAll) {
                                            for(ds of myChart.data.datasets) {
                                                ds.hidden = false;
                                            }
                                        }
                                    }
                                    myChart.update();
                                }
                            }
                        }
                    }
                });
                // Deep copy the monitoring variables
                let info = { my_agent: agent };
                setInterval(function() {
                    // Update the chart every 10s
                    updateChart(info, myChart);
                }, 10000);
            }
            agentCons($("#agent-list"));
        },
        error: function () {
            console.log("error: can not send the request");
        }
    });
});

function int2digit(number) {
    return ("0" + number).slice(-2);
}

function timestamp2string(ts) {
    let myDate = new Date(ts * 1000);
    return int2digit(myDate.getDate()) + "-" + MONTH_STR[myDate.getMonth()] + " " +
        int2digit(myDate.getHours()) + ":" + int2digit(myDate.getMinutes()) + ":" +
        int2digit(myDate.getSeconds());
}

function agentCons(select) {
    let agentName = $(select).val();
    $("div[id$='_chart']").hide();
    $("#" + agentName + "_chart").show();
    $("#agent-name").val(agentName);
}

function updateChart(info, chart) {
    $.ajax({
        type: "GET",
        url: WEBUI + "/user/tempmonitoring/get/" + info.my_agent + "/9s",
        dataType: 'json',
        success: function (data) {
            let m_data = {};
            let new_time = "";
            for(let node in data) {
                let node_data = data[node];
                let node_cons = node_data["consumptions"][0];
                let time_str = timestamp2string(node_cons.time);
                if(!chart.data.labels.includes(time_str)) {
                    // Add a new consumption
                    new_time = time_str;
                    m_data[node] = { x: time_str, y: node_cons.consumption };
                }
            }
            if(new_time.length > 0) {
                // Add new points
                chart.data.labels.push(new_time);
                for(ds of chart.data.datasets) {
                    ds.data.push(m_data[ds.label]);
                }
                chart.update();
            }
        },
        error: function () {
            console.log("error: can not send the request");
        }
    });
}
