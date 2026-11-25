/*
Tool: wazuh-qram-siem
Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.
Software Architect: Sarvepalli Audi Siva Bhanuvardhan
B.Tech CSE (Cybersecurity), Final Year (7th Semester), Dhanalakshmi Srinivasan University,
Tiruchirappalli, Tamil Nadu, India.
Cybersecurity Virtual Internship — Dev/Craft by Fennark: https://devcraft.fennark.xyz
Intern ID: DEV-CRAFT-BQ2VPH | Task 6: Log Monitoring
LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/
GitHub: https://github.com/Sarvepalliaudi
*/
module siem_login_guard #(
    parameter integer WINDOW_CYCLES = 1000,
    parameter integer THRESHOLD = 5
) (
    input wire clk,
    input wire reset_n,
    input wire auth_fail_pulse,
    output reg brute_force_irq,
    output reg [15:0] alert_counter
);
    localparam integer COUNT_WIDTH = (THRESHOLD < 2) ? 1 : $clog2(THRESHOLD + 1);
    localparam integer WINDOW_WIDTH = (WINDOW_CYCLES < 2) ? 1 : $clog2(WINDOW_CYCLES + 1);
    reg [COUNT_WIDTH-1:0] failure_count;
    reg [WINDOW_WIDTH-1:0] window_count;

    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            brute_force_irq <= 1'b0;
            alert_counter <= 16'b0;
            failure_count <= {COUNT_WIDTH{1'b0}};
            window_count <= {WINDOW_WIDTH{1'b0}};
        end else begin
            brute_force_irq <= 1'b0;
            if (window_count == WINDOW_CYCLES - 1) begin
                window_count <= {WINDOW_WIDTH{1'b0}};
                failure_count <= {COUNT_WIDTH{1'b0}};
            end else begin
                window_count <= window_count + 1'b1;
            end

            if (auth_fail_pulse) begin
                if (failure_count + 1'b1 >= THRESHOLD) begin
                    brute_force_irq <= 1'b1;
                    alert_counter <= alert_counter + 1'b1;
                    failure_count <= {COUNT_WIDTH{1'b0}};
                end else begin
                    failure_count <= failure_count + 1'b1;
                end
            end
        end
    end
endmodule
