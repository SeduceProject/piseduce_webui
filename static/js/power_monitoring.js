const MONTH_STR = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Now", "Dec" ];

$(document).ready(function () {
    $.ajax({
        type: "GET",
        url: WEBUI + "/user/powermonitoring/data",
        dataType: 'json',
        success: function (data) {
            for (agent in data) {
                for (switch_name in data[agent]) {
                    let option = document.createElement("option");
                    option.value = switch_name + "@" + agent;
                    option.text = switch_name + "@" + agent;
                    document.getElementById("switch-list").append(option);
                    // Chart colors (https://mokole.com/palette.html)
                    let colors = [ "darkslategray", "darkmagenta", "deepskyblue", "pink",
                        "saddlebrown", "maroon3", "blue", "darkgreen", "red", "coral", "olive",
                        "orange", "fuchsia", "darkslateblue", "yellow", "dodgerblue",
                        "mediumseagreen", "lawngreen", "palegoldenrod", "navy", "blueviolet",
                        "powderblue", "yellowgreen", "springgreen", "deeppink", "crimson",
                        "aqua", "violet" ];
                    // Configure the charts
                    let label_ts = [];
                    let label_values = [];
                    let datasets_values = [];
                    for (port in data[agent][switch_name]) {
                        let one_value = {
                            label: "Port " + port,
                            data: [],
                            fill: false
                        };
                        let port_cons = data[agent][switch_name][port];
                        let nonZero = false;
                        for (cons of port_cons["consumptions"]) {
                            if(!label_ts.includes(cons["time"])) {
                                label_ts.push(cons["time"]);
                            }
                            if(cons["consumption"] > 0) {
                                nonZero = true;
                            }
                            one_value.data.push(cons["consumption"]);
                        }
                        // Add to the chart only ports with non-zero consumption
                        if("node" in port_cons) {
                            one_value.label = port_cons.node;
                        }
                        if(nonZero) {
                            one_value.borderColor = 
                                colors[datasets_values.length % colors.length];
                            datasets_values.push(one_value);
                        }
                    }
                    // Convert the timestamps to Strings
                    for (time of label_ts) {
                        label_values.push(timestamp2string(time));
                    }
                    // Build the chart
					let chartDiv = document.createElement("div");
                    chartDiv.style.width = "900px";
					chartDiv.id = switch_name + "_chart";
                    chartDiv.className = "m-auto";
                    let offSpan = document.createElement("span");
                    offSpan.innerHTML = "<b>Switch ports turned off for more than one hour are ignored.</b>";
					let canvas = document.createElement("canvas");
                    canvas.id = switch_name + "_canvas";
                    chartDiv.append(offSpan);
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
                    let info = { my_agent: agent, my_switch: switch_name };
                    setInterval(function() {
                        // Update the chart every 10s
                        updateChart(info, myChart);
                    }, 10000);
                }
            }
            switchCons($("#switch-list"));
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

function switchCons(select) {
    let switchName = $(select).val().split("@")[0];
    $("div[id$='_chart']").hide();
    $("#" + switchName + "_chart").show();
    $("#switch-name").val(switchName);
}

function updateChart(info, chart) {
    $.ajax({
        type: "GET",
        url: WEBUI + "/user/powermonitoring/get/" + info.my_agent + "/" + info.my_switch + "/9s",
        dataType: 'json',
        success: function (data) {
            let m_data = {};
            let new_time = "";
            for(let port_nb in data[info.my_switch]) {
                let port_data = data[info.my_switch][port_nb];
                let port_cons = port_data["consumptions"][0];
                let time_str = timestamp2string(port_cons.time);
                if(!chart.data.labels.includes(time_str)) {
                    new_time = time_str;
                    if("node" in port_data) {
                        m_data[port_data["node"]] = port_cons.consumption;
                    } else {
                        m_data["Port " + port_nb] = port_cons.consumption;
                    }
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
