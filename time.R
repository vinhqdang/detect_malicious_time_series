detect_ana_mean <- function (x, window_size = 10, alpha = 0.05) {
  N <- length (x)
  outlier_ids <- c()
  for (i in (window_size:N)) {
    # print (i)
    begin_point = i - window_size + 1
    end_point = i
    cur_y <- x[begin_point:end_point]
    # print (cur_y)
    cur_x <- 1:window_size
    l1 <- summary (lm (cur_y ~ cur_x))
    if (l1$coefficients[2,][4] < alpha) {
      print (i)
      outlier_ids <- c(outlier_ids, i)
      print (l1)
      readline(prompt="Press [enter] to continue")
    }
  }
  outlier_ids
}

detect_anomaly_autoencoder <- function (df) {
  require(h2o)
  h2o.init()
  
  df_h <- as.h2o (df)
  df_d <- h2o.deeplearning(x=1:ncol(df), training_frame = df_h, autoencoder = TRUE,
                           activation = "Tanh", hidden = c(64,64,64), epochs = 100)
  errors <- h2o.anomaly(df_d, df_h, per_feature = TRUE)
  er <- as.data.frame (errors)
  # plot (er$reconstr_diff.SE)
  # lines (er$reconstr_avg.SE, col = "red")
  
  print (paste("Correct:", min(which(df$malicious==1))))
  
  require(AnomalyDetection)
  res <- AnomalyDetectionVec(x = er$reconstr_avg.SE, period =5, plot = TRUE, max_anoms = 0.05)
  print (res)
  
  
  # require("tsoutliers")
  # ts1 <- ts (er$reconstr_avg.SE)
  # print (tso (ts1))
  h2o.shutdown(prompt = FALSE)
}

running_average <- function (x, average_size) {
  sapply(average_size:(length(x)-average_size), function(i) mean(x[(i-average_size):(i+average_size)]))
}

detect_anomaly_series <- function (
  x,   # input vector
  average_size = 5, # window size (both ways) to calculate the mean
  down_threshold = 20, # how many times the value goes down before deciding malicious
  down_rate = 1.0,    # if the value goes down down_rate (percent) we decide it is malicious,
  decrease = TRUE,     # find decreasing or increasing subsequence
) {
  x1 <- sapply(average_size:(length(x)-average_size), function(i) mean(x[(i-average_size):(i+average_size)]))
  # x1 <- x
  N = length (x1)
  
  # print (x1)
  plot (x)
  lines (x1, col = "red")
  output <- c()
  for (i in 1:(N - down_threshold)) {
    down_count <- 0
    for (j in 1:down_threshold) {
      if (decrease == TRUE) {  # checking anomaly of difficulty
        if ((i+j) <= N & x1[i+j-1] > x1[i+j]) {
          down_count <- down_count + 1
        }
      } else {   # checking anomaly of avg
        if ((i+j) <= N & x1[i+j-1] < x1[i+j]) {
          down_count <- down_count + 1
        }
      }
    }
    if (down_count >= down_rate * down_threshold) {
      output <- c(output, i)
    }
  }
  abline (v = output[1], lty = 2)
  output
}

detect_anomaly_avg <- function (avg,
                                num,
                                multiple_ratio = 2,
                                min_malicious_num = 150
                                ) 
{
  # B <- 0.001215 * 3 # 0.00125 is a slope of avg on num, generated from data 11k lines
  # A <- 0.429325
  
  # find the correlation between avg ~ num in normal situation
  x <- num[50:min_malicious_num]
  y <- avg[50:min_malicious_num]
  l1 <- lm (y ~ x)
  
  A <- as.numeric(l1$coefficients[1])
  B <- abs(as.numeric(l1$coefficients[2])) * multiple_ratio
  
  if (length(avg) != length(num)) {
    print ("Different length")
    stop()
  }
  
  N <- length (avg)
  output <- c()
  for (i in 1:N) {
    upper_bound <- B * num[i] + A
    if (avg[i] > upper_bound & i > min_malicious_num) {
      output <- c(output, i)
    }
  }
  plot (avg ~ num)
  abline (a = A, b = B, col = "red")
  
  # remove accident peak points
  abline (v = output[1], lty = 2)
  output
}

find_longest_decrease <- function (x) {
  N <- length (x)
  output <- c() #length (output) should be = N
  for (i in 1:N) {
    if (i %% 1000 == 0) {
      print (paste ("Process data number", i))
      print (paste("Current maximum:", max(output)))
      print (paste("Index of max:", min(which (output == max(output)))))
    }
    cur_decrease <- 0
    if (i == 1) {
      for (j in 1:(N-i)) {
        if ((i+j) <= N & x[i+j-1] > x[i+j]) {
          cur_decrease <- cur_decrease + 1
        } else {
          break()
        }
      }
    } else if (i > 1 & output [i-1] == 0) {
      for (j in 1:(N-i)) {
        if ((i+j) <= N & x[i+j-1] > x[i+j]) {
          cur_decrease <- cur_decrease + 1
        } else {
          break()
        }
      }
    } else {
      cur_decrease <- output[i-1] - 1
    }
    output <- c (output, cur_decrease)
  }
  output
}

# implement naive Brute Force Euclidean Distance in 
# "Jones, M.J.; Nikovski, D.N.; Imamura, M.; Hirata, T., 
# "Exemplar Learning for Extremely Efficient Anomaly Detection in Real-Valued Time Series", 
# Journal of Data Mining and Knowledge Discovery, 
# DOI: 10.1007/s10618-015-0449-3, ISSN: 1573-756X, Vol. 30, No. 6, pp. 1427-1454, March 2016."
BFED <- function (train_series, test_series, subsequence_len)
{
  # train_series: T[1..n]: no anomaly
  # test_series: Q[1..m]
  # subsequence_len: w
  # output: vector S[1..m-w] as anomaly score
  n <- length(train_series)
  m <- length(test_series)
  w <- subsequence_len
  S <- c()
  for (i in 1:(m-w)) {
    bsf <- Inf
    for (j in 1:(n-w)) {
      d <- 0
      for (k in 1:w) {
        d <- d + (train_series[j+k] - test_series[i+k])^2
        if (d < bsf) {
          bsf <- d
        }
      }
    }
    S <- c(S, bsf)
  }
  S
}